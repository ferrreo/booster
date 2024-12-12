package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavaliergopher/cpio"
	"gopkg.in/yaml.v3"
)

// An internal structure that represents configuration for the generator.
// It is essentially combination of UserConfig + flags
type generatorConfig struct {
	networkConfigType       netConfigType
	networkStaticConfig     *networkStaticConfig
	networkActiveInterfaces []net.HardwareAddr
	universal               bool
	modules                 []string // extra modules to add
	modulesForceLoad        []string // extra modules to load at the boot time
	appendAllModAliases     bool
	compression             string
	timeout                 time.Duration
	extraFiles              []string
	output                  string
	forceOverwrite          bool // overwrite output file
	initBinary              string
	kernelVersion           string
	modulesDir              string
	debug                   bool
	readDeviceAliases       func() (set, error)
	readHostModules         func(kernelVer string) (set, error)
	readModprobeOptions     func() (map[string]string, error)
	stripBinaries           bool
	enableLVM               bool
	enableMdraid            bool
	mdraidConfigPath        string
	enableZfs               bool
	zfsImportParams         string
	zfsCachePath            string

	// virtual console configs
	enableVirtualConsole     bool
	vconsolePath, localePath string
	enablePlymouth           bool
}

type networkStaticConfig struct {
	ip         string
	gateway    string
	dnsServers string // comma-separated list
}

type netConfigType int

const (
	netOff netConfigType = iota
	netDhcp
	netStatic
)

var (
	imageModulesDir = "/usr/lib/modules/"
	firmwareDir     = "/usr/lib/firmware/"
)

// List of GPU modules to exclude (similar to initramfs-tools script)
var excludedGPUModules = []string{
	"mga", "r128", "savage", "sis", "tdfx", "via", "panfrost",
}

// Modified defaultModulesList
var defaultModulesList = []string{
	"kernel/fs/",
	"kernel/arch/x86/crypto/",
	"kernel/crypto/",
	"kernel/drivers/input/serio/",
	"kernel/drivers/input/keyboard/",
	"kernel/drivers/md/",
	"kernel/drivers/char/tpm/",
	"kernel/drivers/usb/host/",
	"kernel/drivers/hid/",
	"kernel/drivers/ata/",
	"kernel/drivers/scsi/",
	"hid_generic", "usbhid", "sd_mod", "ahci",
	"sdhci", "sdhci_acpi", "sdhci_pci", "mmc_block", // mmc
	"nvme", "usb_storage", "uas",
	"efivarfs",
	"virtio_pci", "virtio_blk", "virtio_scsi", "virtio_crypto",
	"mptspi", "vmd",
}

func generateInitRamfs(conf *generatorConfig) error {
	if _, err := os.Stat(conf.output); (err == nil || !os.IsNotExist(err)) && !conf.forceOverwrite {
		return fmt.Errorf("File %v exists, please specify --force if you want to overwrite it", conf.output)
	}

	img, err := NewImage(conf.output, conf.compression, conf.stripBinaries)
	if err != nil {
		return err
	}
	defer img.Cleanup()

	if err := appendCompatibilitySymlinks(img); err != nil {
		return err
	}

	if err := img.appendInitBinary(conf.initBinary); err != nil {
		return err
	}

	if err := img.appendExtraFiles(conf.extraFiles...); err != nil {
		return err
	}

	kmod, err := NewKmod(conf)
	if err != nil {
		return err
	}

	// some kernels might be compiled without some of the modules (e.g. virtio) from the predefined list
	// generator should not fail if a module is not detected
	if err := kmod.activateModules(true, false, defaultModulesList...); err != nil {
		return err
	}

	// Ensure simpledrm and its dependencies are included and force-loaded if Plymouth is enabled
	if conf.enablePlymouth {
		if err := kmod.activateModules(false, true, "video", "wmi", "simpledrm", "drm_kms_helper", "drm_ttm_helper", "drm_display_helper", "ttm"); err != nil {
			debug("Failed to include simpledrm module: %v", err)
		}
		// Force-load simpledrm at boot time
		conf.modulesForceLoad = append(conf.modulesForceLoad, "video", "wmi", "simpledrm", "drm_kms_helper", "drm_ttm_helper", "drm_display_helper", "ttm")
	}

	if err := kmod.activateModules(false, true, conf.modules...); err != nil {
		return err
	}
	if err := kmod.activateModules(false, true, conf.modulesForceLoad...); err != nil {
		return err
	}

	// Hacky fix for hid issues in newer kernels
	if err := kmod.activateModules(false, false, "usbhid", "hid_generic"); err != nil {
		return err
	}
	conf.modulesForceLoad = append(conf.modulesForceLoad, "usbhid", "hid_generic")

	// cbc module is a hard requirement for "encrypted_keys"
	// https://github.com/torvalds/linux/blob/master/security/keys/encrypted-keys/encrypted.c#L42
	kmod.addExtraDep("encrypted_keys", "cbc")

	if conf.networkConfigType != netOff {
		if err := kmod.activateModules(true, false, "kernel/drivers/net/ethernet/"); err != nil {
			return err
		}
	}

	if conf.enableLVM {
		if err := kmod.activateModules(false, false, "dm_mod", "dm_snapshot", "dm_mirror", "dm_cache", "dm_cache_smq", "dm_thin_pool"); err != nil {
			return err
		}

		conf.modulesForceLoad = append(conf.modulesForceLoad, "dm_mod")
		if err := img.appendExtraFiles("lvm"); err != nil {
			return err
		}
	}

	if conf.enableMdraid {
		if err := kmod.activateModules(true, true, "kernel/drivers/md/"); err != nil {
			return err
		}

		// preload md_mod for speed. Level-specific drivers (e.g. raid1, raid456) are going to be detected loaded at boot-time
		conf.modulesForceLoad = append(conf.modulesForceLoad, "md_mod")

		if err := img.appendExtraFiles("mdadm"); err != nil {
			return err
		}

		mdadmConf := conf.mdraidConfigPath
		if mdadmConf == "" {
			mdadmConf = "/etc/mdadm.conf"
		}
		content, err := os.ReadFile(mdadmConf)
		if err != nil {
			return err
		}
		if err := img.AppendContent("/etc/mdadm.conf", 0o644, content); err != nil {
			return err
		}
	}

	if conf.enableZfs {
		if err := kmod.activateModules(false, true, "zfs"); err != nil {
			return err
		}
		conf.modulesForceLoad = append(conf.modulesForceLoad, "zfs")

		if err := img.appendExtraFiles("zpool", "zfs"); err != nil {
			return err
		}

		zfsCachePath := conf.zfsCachePath
		if zfsCachePath == "" {
			zfsCachePath = "/etc/zfs/zpool.cache"
		}
		content, err := os.ReadFile(zfsCachePath)
		if err != nil {
			return err
		}
		if err := img.AppendContent("/etc/zfs/zpool.cache", 0o644, content); err != nil {
			return err
		}

		if err := img.AppendFile("/etc/default/zfs"); err != nil {
			if os.IsNotExist(err) {
				debug("Adding /etc/default/zfs to the image: %v", err)
			} else {
				return err
			}
		}
	}

	if err := kmod.resolveDependencies(); err != nil {
		return err
	}
	if err := kmod.addModulesToImage(img); err != nil {
		return err
	}

	var aliases []alias
	if conf.appendAllModAliases {
		aliases = kmod.aliases
	} else {
		// collect aliases for required modules only
		aliases, err = kmod.filterAliasesForRequiredModules(conf)
		if err != nil {
			return err
		}
	}
	if err := img.appendAliasesFile(aliases); err != nil {
		return err
	}

	kmod.filterModprobeForRequiredModules()

	var vconsole *VirtualConsole
	if conf.enableVirtualConsole {
		vconsole, err = img.enableVirtualConsole(conf.vconsolePath, conf.localePath)
		if err != nil {
			return err
		}
	}

	if err := img.appendInitConfig(conf, kmod, vconsole); err != nil {
		return err
	}

	// appending initrd-release file per recommendation from https://systemd.io/INITRD_INTERFACE/
	if err := img.AppendContent("/etc/initrd-release", 0o644, []byte{}); err != nil {
		return err
	}

	if err := img.addPlymouthSupport(conf); err != nil {
		return err
	}

	return img.Close()
}

// appendCompatibilitySymlinks appends symlinks for compatibility with older firmware that loads extra files from non-standard locations
func appendCompatibilitySymlinks(img *Image) error {
	symlinks := []struct{ src, target string }{
		{"/lib", "usr/lib"},
		{"/usr/local/lib", "../lib"},
		{"/usr/sbin", "bin"},
		{"/bin", "usr/bin"},
		{"/sbin", "usr/bin"},
		{"/usr/local/bin", "../bin"},
		{"/usr/local/sbin", "../bin"},
		{"/var/run", "../run"},
		{"/usr/lib64", "lib"},
		{"/lib64", "usr/lib"},
	}

	for _, l := range symlinks {
		// Ensure that target always exist which may not be the
		// case if we only install files from /lib or /bin.
		targetDir := filepath.Join(filepath.Dir(l.src), l.target)
		if err := img.AppendDirEntry(targetDir); err != nil {
			return err
		}

		mode := cpio.FileMode(0o777) | cpio.TypeSymlink
		if err := img.AppendEntry(l.src, mode, []byte(l.target)); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendInitBinary(initBinary string) error {
	content, err := os.ReadFile(initBinary)
	if err != nil {
		return fmt.Errorf("%s: %v", initBinary, err)
	}
	return img.AppendContent("/init", 0o755, content)
}

func (img *Image) appendExtraFiles(binaries ...string) error {
	for _, f := range binaries {
		if !filepath.IsAbs(f) {
			// If the given name is not an absolute path, assume that it refers
			// to an executable and lookup the path to the executable using $PATH.
			var err error
			f, err = lookupPath(f)
			if err != nil {
				return err
			}
		}

		if err := img.AppendFile(f); err != nil {
			return err
		}
	}
	return nil
}

func lookupPath(binary string) (string, error) {
	paths := []string{
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}

	for _, p := range paths {
		f := filepath.Join(p, binary)
		_, err := os.Stat(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		return f, nil
	}

	return "", os.ErrNotExist
}

func findFwFile(fw string) (string, error) {
	supportedFwExt := []string{
		"",
		".xz",  // since linux v5.3
		".zst", // since linux v5.19
	}

	fwBasePath := firmwareDir + fw
	for _, ext := range supportedFwExt {
		fwPath := fwBasePath + ext
		if _, err := os.Stat(fwPath); err == nil {
			return fwPath, nil
		} else if os.IsNotExist(err) {
			continue // try the next extension
		} else {
			return "", err
		}
	}

	return "", os.ErrNotExist
}

func (img *Image) appendFirmwareFiles(modName string, fws []string) error {

	for _, fw := range fws {
		path, err := findFwFile(fw)

		if os.IsNotExist(err) {
			debug("module %s depends on firmware %s but the firmware file does not exist", modName, fw)
			continue
		} else if err != nil {
			return err
		}

		if err := img.AppendFile(path); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendInitConfig(conf *generatorConfig, kmod *Kmod, vconsole *VirtualConsole) error {
	var initConfig InitConfig // config for init stored to /etc/booster.init.yaml

	initConfig.MountTimeout = int(conf.timeout.Seconds())
	initConfig.Kernel = conf.kernelVersion
	initConfig.ModuleDependencies = kmod.dependencies
	initConfig.ModulePostDependencies = kmod.postDependencies
	initConfig.ModulesForceLoad = kmod.selectNonBuiltinModules(conf.modulesForceLoad)
	initConfig.ModprobeOptions = kmod.modprobeOptions
	initConfig.BuiltinModules = kmod.builtinModules
	initConfig.VirtualConsole = vconsole
	initConfig.EnablePlymouth = conf.enablePlymouth
	initConfig.EnableLVM = conf.enableLVM
	initConfig.EnableMdraid = conf.enableMdraid
	initConfig.EnableZfs = conf.enableZfs
	initConfig.ZfsImportParams = conf.zfsImportParams

	if conf.networkConfigType == netDhcp {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.Dhcp = true
	} else if conf.networkConfigType == netStatic {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.IP = conf.networkStaticConfig.ip
		initConfig.Network.Gateway = conf.networkStaticConfig.gateway
		initConfig.Network.DNSServers = conf.networkStaticConfig.dnsServers
	}
	if conf.networkActiveInterfaces != nil {
		initConfig.Network.Interfaces = conf.networkActiveInterfaces
	}

	content, err := yaml.Marshal(initConfig)
	if err != nil {
		return err
	}

	return img.AppendContent(initConfigPath, 0o644, content)
}

func (img *Image) appendAliasesFile(aliases []alias) error {
	var buff bytes.Buffer
	for _, a := range aliases {
		buff.WriteString(a.pattern)
		buff.WriteString(" ")
		buff.WriteString(a.module)
		buff.WriteString("\n")
	}
	return img.AppendContent(imageModulesDir+"booster.alias", 0o644, buff.Bytes())
}

func (img *Image) addPlymouthSupport(conf *generatorConfig) error {
	if !conf.enablePlymouth {
		return nil
	}

	themeCmd := exec.Command("/usr/sbin/plymouth-set-default-theme")
	themeBytes, err := themeCmd.Output()
	if err != nil {
		conf.enablePlymouth = false
		return fmt.Errorf("failed to get default theme: %v", err)
	}
	theme := strings.TrimSpace(string(themeBytes))
	if theme == "" {
		conf.enablePlymouth = false
		return nil
	}

	if err := img.appendExtraFiles(
		"/bin/plymouth",
		"/sbin/plymouthd",
		"/usr/libexec/plymouth/plymouthd-fd-escrow",
	); err != nil {
		conf.enablePlymouth = false
		return err
	}

	pluginCmd := exec.Command("plymouth", "--get-splash-plugin-path")
	pluginPath, err := pluginCmd.Output()
	if err != nil {
		conf.enablePlymouth = false
		return fmt.Errorf("failed to get plugin path: %v", err)
	}
	pluginDir := strings.TrimSpace(string(pluginPath))

	// Add all plugins from the plugin directory
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		conf.enablePlymouth = false
		return fmt.Errorf("failed to read plugin directory: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".so") {
			pluginFile := filepath.Join(pluginDir, entry.Name())
			if err := img.AppendFile(pluginFile); err != nil {
				debug("Plymouth plugin not found: %v", err)
			}
		}
	}

	// Add theme-specific files
	themesDir := "/usr/share/plymouth/themes"
	themeDir := filepath.Join(themesDir, theme)
	if err := img.AppendRecursive(themeDir); err != nil {
		conf.enablePlymouth = false
		return fmt.Errorf("failed to add theme directory: %v", err)
	}

	// Add base themes
	if err := img.AppendRecursive(filepath.Join(themesDir, "details")); err != nil {
		debug("Failed to add details theme: %v", err)
	}
	if err := img.AppendRecursive(filepath.Join(themesDir, "text")); err != nil {
		debug("Failed to add text theme: %v", err)
	}

	// Add renderers
	rendererDir := filepath.Join(pluginDir, "renderers")
	entries, err = os.ReadDir(rendererDir)
	if err != nil {
		debug("Failed to read renderer directory: %v", err)
	} else {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".so") {
				if err := img.AppendFile(filepath.Join(rendererDir, entry.Name())); err != nil {
					debug("Plymouth renderer not found: %v", err)
				}
			}
		}
	}

	// Add config files
	if err := img.AppendFile("/etc/plymouth/plymouthd.conf"); err != nil {
		debug("Plymouth config not found: %v", err)
	}
	if err := img.AppendFile("/usr/share/plymouth/plymouthd.defaults"); err != nil {
		debug("Plymouth defaults not found: %v", err)
	}

	// Add OS release info
	if err := img.AppendFile("/etc/os-release"); err != nil {
		debug("OS release info not found: %v", err)
	}

	// Add all Plymouth PNG files
	plymouthDir := "/usr/share/plymouth"
	err = filepath.Walk(plymouthDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".png") {
			if err := img.AppendFile(path); err != nil {
				debug("Plymouth image not found: %v", err)
			}
		}
		return nil
	})
	if err != nil {
		debug("Error walking Plymouth directory: %v", err)
	}

	// Add font support for graphical themes
	if theme != "text" && theme != "details" {
		if err := img.AppendFile("/usr/share/plymouth/debian-logo.png"); err != nil {
			debug("Plymouth logo not found: %v", err)
		}

		if err := img.AppendFile("/etc/fonts/fonts.conf"); err != nil {
			debug("Fontconfig config not found: %v", err)
		}
		if err := img.AppendFile("/etc/fonts/conf.d/60-latin.conf"); err != nil {
			debug("Latin font config not found: %v", err)
		}

		// Add DejaVu fonts
		fontPaths := []string{
			"/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
			"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		}
		for _, font := range fontPaths {
			if err := img.AppendFile(font); err != nil {
				debug("Font file not found: %v", err)
			}
		}
	}

	return nil
}

func (img *Image) AppendRecursive(path string) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return img.AppendFile(filePath)
		}
		return nil
	})
}
