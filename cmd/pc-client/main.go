package main

import (
	"image/color"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall" // <-- ДОБАВЛЕН ИМПОРТ ДЛЯ СКРЫТИЯ ОКОН
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/windows"

	mobile "github.com/ghostquic/ghost-quic-v2/mobile-src"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

var (
	isRunning bool
	mu        sync.Mutex
)

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

func elevate() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := windows.UTF16PtrFromString(verb)
	exePtr, _ := windows.UTF16PtrFromString(exe)
	cwdPtr, _ := windows.UTF16PtrFromString(cwd)
	argPtr, _ := windows.UTF16PtrFromString(args)

	var showCmd int32 = 1
	err := windows.ShellExecute(windows.Handle(0), verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		log.Fatalf("Не удалось запросить права: %v", err)
	}
	os.Exit(0)
}

// Вспомогательная функция для скрытого запуска команд
func runHiddenCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

// Получаем IP шлюза и индекс интерфейса по умолчанию (скрыто)
func getDefaultGateway() (string, string) {
	cmd := exec.Command("powershell", "-Command", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 | ForEach-Object { $_.NextHop + ' ' + $_.ifIndex }")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	parts := strings.Fields(string(out))
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func setupRoutes() {
	serverIP := "89.22.232.244"
	gw, ifIdx := getDefaultGateway()
	
	if gw != "" && ifIdx != "" {
		log.Printf("[PC Client] Исключаем IP сервера %s через шлюз %s (ifIndex: %s)", serverIP, gw, ifIdx)
		runHiddenCommand("route", "add", serverIP, "mask", "255.255.255.255", gw, "if", ifIdx, "metric", "1")
	} else {
		log.Println("[PC Client] ВНИМАНИЕ: Не удалось определить шлюз по умолчанию!")
	}
}

func configureTUN() {
	log.Println("[PC Client] Настройка IP и маршрутов TUN-адаптера...")
	time.Sleep(2 * time.Second)
	
	runHiddenCommand("netsh", "interface", "ipv4", "set", "address", "name=\"wintun\"", "static", "10.0.0.1", "255.255.255.0")
	runHiddenCommand("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/0", "wintun", "10.0.0.2", "metric=1")
	log.Println("[PC Client] Маршруты добавлены. Весь трафик идет через VPN.")
}

func cleanupTUN() {
	log.Println("[PC Client] Удаление маршрутов...")
	serverIP := "89.22.232.244"
	runHiddenCommand("route", "delete", serverIP)
	runHiddenCommand("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/0", "wintun")
}

func main() {
	exe, _ := os.Executable()
	os.Chdir(filepath.Dir(exe))

	if !isAdmin() {
		elevate()
	}

	myApp := app.New()
	myApp.Settings().SetTheme(MyTheme{})
	myWindow := myApp.NewWindow("HyperFlow System VPN")
	myWindow.Resize(fyne.NewSize(450, 550))

	statusLabel := widget.NewLabel("ОТКЛЮЧЕНО")
	statusLabel.Alignment = fyne.TextAlignCenter
	statusLabel.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}

	radioGroup := widget.NewRadioGroup([]string{"REALITY", "HYSTERIA 2"}, func(s string) {})
	radioGroup.Horizontal = true
	radioGroup.SetSelected("REALITY")

	logBox := widget.NewMultiLineEntry()
	logBox.Wrapping = fyne.TextWrapWord
	logBox.SetMinRowsVisible(12)

	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err == nil {
		multiWriter := io.MultiWriter(logFile, writerFunc(func(p []byte) (n int, err error) {
			fyne.Do(func() {
				logBox.SetText(logBox.Text + string(p))
			})
			return len(p), nil
		}))
		log.SetOutput(multiWriter)
	}

	btnConnect := widget.NewButton("ПОДКЛЮЧИТЬ", func() {})

	btnConnect.OnTapped = func() {
		mu.Lock()
		defer mu.Unlock()

		if !isRunning {
			if _, err := os.Stat("wintun.dll"); os.IsNotExist(err) {
				log.Println("[ОШИБКА] Файл wintun.dll не найден рядом с программой!")
				return
			}

			btnConnect.SetText("ПОДКЛЮЧЕНИЕ...")
			
			serverAddr := "89.22.232.244:9444"
			pubKeyHex := "e1edfb073368fd76d519c820843a88a37850729514a1d33096be70e76273c564"
			socksAddr := "127.0.0.1:1080"

			setupRoutes()

			var res string
			if radioGroup.Selected == "HYSTERIA 2" {
				log.Println("[PC Client] Режим: HYSTERIA 2")
				hy2Addr := "89.22.232.244:20000"
				hy2Pass := "hCmVAC95Aec/MimFgJOJgQ=="
				res = mobile.StartHysteriaClient(hy2Addr, hy2Pass, socksAddr)
			} else {
				log.Println("[PC Client] Режим: REALITY")
				res = mobile.StartClient(serverAddr, pubKeyHex, socksAddr)
			}
			
			log.Println("[PC Client] Статус запуска:", res)
			if res != "Client started successfully" {
				log.Println("Ошибка запуска туннеля.")
				btnConnect.SetText("ПОДКЛЮЧИТЬ")
				return
			}

			log.Println("[PC Client] Инициализация TUN-адаптера...")
			key := &engine.Key{
				Device:   "wintun",
				Proxy:    "socks5://" + socksAddr,
				LogLevel: "info",
				MTU:      1500,
			}
			engine.Insert(key)
			
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[FATAL] Паника в TUN: %v\n", r)
					}
				}()
				engine.Start()
			}()

			go configureTUN()

			isRunning = true
			statusLabel.SetText("ЗАЩИЩЕНО")
			btnConnect.SetText("ОТКЛЮЧИТЬ")
			log.Println("[PC Client] Системный VPN запущен!")

		} else {
			btnConnect.SetText("ОТКЛЮЧЕНИЕ...")
			go func() {
				log.Println("[PC Client] Остановка TUN...")
				engine.Stop()
				cleanupTUN()
				mobile.StopClient()
				
				fyne.Do(func() {
					isRunning = false
					statusLabel.SetText("ОТКЛЮЧЕНО")
					btnConnect.SetText("ПОДКЛЮЧИТЬ")
					log.Println("[PC Client] Остановлен.")
				})
			}()
		}
	}

	top := container.NewVBox(
		widget.NewLabelWithStyle("HyperFlow System VPN", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		statusLabel,
		widget.NewSeparator(),
		radioGroup,
		btnConnect,
		widget.NewSeparator(),
	)

	content := container.NewBorder(top, nil, nil, nil, logBox)
	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

type writerFunc func([]byte) (int, error)
func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type MyTheme struct{}
func (m MyTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color { return theme.DefaultTheme().Color(name, theme.VariantDark) }
func (m MyTheme) Font(style fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(style) }
func (m MyTheme) Icon(name fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(name) }
func (m MyTheme) Size(name fyne.ThemeSizeName) float32 { return theme.DefaultTheme().Size(name) }