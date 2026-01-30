package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// NetworkConfig holds network policy settings
type NetworkConfig struct {
	AllowedHosts []string `json:"allowed_hosts"` // host:port patterns allowed
	DenyAll      bool     `json:"deny_all"`      // default deny if true
}

// Config represents the nanofile configuration
type Config struct {
	Args                []string               `json:"Args"`
	Program             string                 `json:"Program"`
	ManifestPassthrough map[string]interface{} `json:"ManifestPassthrough"`
	Env                 map[string]string      `json:"Env"`
	Files               map[string]string      `json:"Files"`
	Policy              string                 `json:"Policy"`  // Path to policy JSON file
	Network             *NetworkConfig         `json:"Network"` // Network access policy
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "run":
		runApp(os.Args[2:])
	case "mkimage":
		mkImageOnly(os.Args[2:])
	case "deploy":
		deployTool(os.Args[2:])
	case "tools":
		listTools(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `minops - Minimal Nanos ops with Authority Kernel

Usage:
  minops run <app.py|app.js|app.ts> [-c config.json] [-m memory] [-p policy.json] [-v]
  minops deploy <tool.wasm> [-p policy.json] [-n name]
  minops tools [-l]
  minops proxy [-s socket] [--llm-provider openai] [--llm-endpoint url]

Commands:
  run       Run a Python/Node.js application in Nanos with Authority Kernel
  deploy    Deploy a WASM tool to the tool registry
  tools     List deployed tools
  proxy     Start the akproxy daemon for HTTP/LLM services

Run Options:
  -c config.json    Configuration file (default: config.json)
  -p policy.json    Authority Kernel policy file
  -m memory         Memory in MB (default: 512)
  -v, -verbose      Verbose output
  --allow-host h    Allow network access to host:port (can repeat)
  --allow-llm       Allow common LLM API endpoints (OpenAI, Anthropic, etc.)

Deploy Options:
  -p policy.json    Tool capability policy
  -n name           Tool name (default: derived from filename)
  --signature sig   Signature file for verification

Tools Options:
  -l, --list        List all deployed tools

Proxy Options:
  -s socket         Unix socket path (default: /tmp/akproxy.sock)
  --llm-provider    LLM provider: openai, anthropic, ollama
  --llm-endpoint    LLM API endpoint URL
  --allowed-dirs    Comma-separated allowed directories

Examples:
  minops run main.py -c config.json
  minops run main.ts --allow-llm                 # Allow OpenAI, Anthropic, etc.
  minops run app.js --allow-host api.custom.com:443
  minops run examples/01_heap_operations.py -p examples/policies/01_heap_policy.json
  minops run examples/01-heap-operations.ts -p examples/policies/01_heap_policy.json
  minops deploy mytool.wasm -p tool_policy.json -n my_tool
  minops tools --list
  minops proxy --llm-provider openai --llm-endpoint https://api.openai.com

`)
}

// Common LLM API endpoints for --allow-llm flag
var llmEndpoints = []string{
	"api.openai.com:443",
	"api.anthropic.com:443",
	"generativelanguage.googleapis.com:443",
	"api.cohere.ai:443",
	"api.mistral.ai:443",
	"api.groq.com:443",
	"api.together.xyz:443",
	"api.replicate.com:443",
	"api.fireworks.ai:443",
	"huggingface.co:443",
	"api-inference.huggingface.co:443",
}

// detectAppType determines the runtime based on file extension
func detectAppType(appFile string) string {
	ext := strings.ToLower(filepath.Ext(appFile))
	switch ext {
	case ".py":
		return "python"
	case ".js", ".mjs", ".ts":
		return "node"
	default:
		return "unknown"
	}
}

func runApp(args []string) {
	var (
		appFile      string
		configFile   = "config.json"
		policyFile   = ""
		memory       = 512
		verbose      bool
		allowedHosts []string
		allowLLM     bool
	)

	// Parse command line arguments manually to handle flags after positional args
	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-v", "-verbose":
			verbose = true
		case "-c":
			if i+1 < len(args) {
				configFile = args[i+1]
				i++
			}
		case "-p":
			if i+1 < len(args) {
				policyFile = args[i+1]
				i++
			}
		case "-m":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					memory = n
					i++
				}
			}
		case "--allow-host":
			if i+1 < len(args) {
				allowedHosts = append(allowedHosts, args[i+1])
				i++
			}
		case "--allow-llm":
			allowLLM = true
		default:
			remaining = append(remaining, arg)
		}
	}

	if len(remaining) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No app specified\n")
		printUsage()
		os.Exit(1)
	}

	appFile = remaining[0]

	// Verify app exists
	if _, err := os.Stat(appFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot find app: %s\n", appFile)
		os.Exit(1)
	}

	// Ensure rootfs exists (extracts from Docker if needed)
	if err := ensureRootfs(verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up rootfs: %v\n", err)
		os.Exit(1)
	}

	// Load config
	config := &Config{
		Args: []string{filepath.Base(appFile)},
	}

	if _, err := os.Stat(configFile); err == nil {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		if err := json.Unmarshal(data, config); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config: %v\n", err)
			os.Exit(1)
		}
	}

	// Auto-detect or use specified policy file
	if policyFile == "" {
		policyFile = findPolicyFile(appFile)
	}
	if policyFile != "" {
		if _, err := os.Stat(policyFile); err == nil {
			config.Policy = policyFile
		}
	}

	// Merge --allow-llm endpoints with explicit --allow-host entries
	if allowLLM {
		allowedHosts = append(allowedHosts, llmEndpoints...)
	}

	// Store allowed hosts in config for manifest generation
	if len(allowedHosts) > 0 {
		if config.Network == nil {
			config.Network = &NetworkConfig{}
		}
		config.Network.AllowedHosts = allowedHosts
	}

	if verbose {
		fmt.Printf("🔧 Configuration:\n")
		fmt.Printf("   App: %s\n", appFile)
		fmt.Printf("   Args: %v\n", config.Args)
		fmt.Printf("   Memory: %dMB\n", memory)
		fmt.Printf("   Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		if config.Policy != "" {
			fmt.Printf("   Policy: %s\n", config.Policy)
		}
		if len(allowedHosts) > 0 {
			fmt.Printf("   Allowed hosts: %d endpoints\n", len(allowedHosts))
			for _, h := range allowedHosts {
				fmt.Printf("     - %s\n", h)
			}
		}
		fmt.Printf("\n")
	}

	// Create temporary directory for image
	tmpDir, err := ioutil.TempDir("", "minops-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	if verbose {
		fmt.Printf("📂 Temp directory: %s\n", tmpDir)
	}

	// Copy app to temp directory
	tmpApp := filepath.Join(tmpDir, filepath.Base(appFile))
	if err := copyFile(appFile, tmpApp); err != nil {
		fmt.Fprintf(os.Stderr, "Error copying app: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Copied app to: %s\n", tmpApp)
	}

	// Find kernel image
	kernelPath := findKernelImage()
	if kernelPath == "" {
		fmt.Fprintf(os.Stderr, "Error: Cannot find kernel image\n")
		fmt.Fprintf(os.Stderr, "Build with: make -j$(nproc)\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Found kernel: %s\n", kernelPath)
	}

	// Create minimal image with app
	imagePath := filepath.Join(tmpDir, "image.raw")
	if err := createImage(imagePath, tmpApp, kernelPath, config, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating image: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Created image: %s\n", imagePath)
		fmt.Printf("\n")
	}

	// Launch QEMU
	fmt.Printf("🚀 Launching kernel...\n\n")
	if err := launchQEMU("", imagePath, config, memory, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error launching QEMU: %v\n", err)
		os.Exit(1)
	}
}

func mkImageOnly(args []string) {
	var (
		appFile    string
		configFile = "config.json"
		verbose    bool
	)

	// Parse command line arguments manually to handle flags after positional args
	// Go's flag package doesn't handle this well by default
	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-v", "-verbose":
			verbose = true
		case "-c":
			if i+1 < len(args) {
				configFile = args[i+1]
				i++
			}
		default:
			remaining = append(remaining, arg)
		}
	}

	if len(remaining) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: minops mkimage <app.py> <output.img> [-c config.json] [-v]\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("🔧 Verbose mode enabled\n")
	}

	appFile = remaining[0]
	imagePath := remaining[1]

	// Verify app exists
	if _, err := os.Stat(appFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot find app: %s\n", appFile)
		os.Exit(1)
	}

	// Load config
	config := &Config{
		Args: []string{filepath.Base(appFile)},
	}

	if _, err := os.Stat(configFile); err == nil {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		if err := json.Unmarshal(data, config); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config: %v\n", err)
			os.Exit(1)
		}
	}

	if verbose {
		fmt.Printf("🔧 Configuration:\n")
		fmt.Printf("   App: %s\n", appFile)
		fmt.Printf("   Image: %s\n", imagePath)
		fmt.Printf("   Args: %v\n", config.Args)
		fmt.Printf("\n")
	}

	// Find kernel image
	kernelPath := findKernelImage()
	if kernelPath == "" {
		fmt.Fprintf(os.Stderr, "Error: Cannot find kernel image\n")
		fmt.Fprintf(os.Stderr, "Build with: make -j$(nproc)\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Found kernel: %s\n", kernelPath)
	}

	// Create image
	if err := createImage(imagePath, appFile, kernelPath, config, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating image: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Created image: %s\n", imagePath)
		fi, _ := os.Stat(imagePath)
		if fi != nil {
			fmt.Printf("   Size: %d bytes\n", fi.Size())
		}
	} else {
		fmt.Printf("✅ Created image: %s\n", imagePath)
	}
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func findKernelImage() string {
	// Try standard locations including cache
	candidates := []string{
		"/tmp/nanos-kernel/kernel.img",
		"output/platform/pc/bin/kernel.img",
		"../output/platform/pc/bin/kernel.img",
		"../../output/platform/pc/bin/kernel.img",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func findMkfs() string {
	// Try standard locations
	candidates := []string{
		"output/tools/bin/mkfs",
		"../output/tools/bin/mkfs",
		"../../output/tools/bin/mkfs",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func findBootloader() string {
	// Try standard locations including cache
	candidates := []string{
		"/tmp/nanos-kernel/boot.img",
		"output/platform/pc/boot/boot.img",
		"../output/platform/pc/boot/boot.img",
		"../../output/platform/pc/boot/boot.img",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// findPolicyFile auto-detects policy file based on script name
// For example: examples/01_heap_operations.py -> examples/policies/01_heap_policy.json
// Or: examples/01-heap-operations.ts -> examples/policies/01_heap_policy.json
func findPolicyFile(appFile string) string {
	basename := filepath.Base(appFile)
	dir := filepath.Dir(appFile)
	// Remove extension to get base name
	nameWithoutExt := strings.TrimSuffix(basename, filepath.Ext(basename))

	// Map script names to policy files (handles both Python and Node.js)
	policyMapping := map[string]string{
		"01_heap_operations": "01_heap_policy.json",
		"01-heap-operations": "01_heap_policy.json",
		"02_authorization":   "02_authorization_policy.json",
		"02-authorization":   "02_authorization_policy.json",
		"03_tool_execution":  "03_tool_policy.json",
		"03-tool-execution":  "03_tool_policy.json",
		"04_inference":       "04_inference_policy.json",
		"04-inference":       "04_inference_policy.json",
		"05_audit_logging":   "05_audit_policy.json",
		"05-audit-logging":   "05_audit_policy.json",
	}

	if policyName, ok := policyMapping[nameWithoutExt]; ok {
		// Look for policy in examples/policies/ relative to app
		candidates := []string{
			filepath.Join(dir, "policies", policyName),
			filepath.Join(dir, "..", "examples", "policies", policyName),
			filepath.Join("examples", "policies", policyName),
		}

		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	// Also check for a policy file with matching number prefix
	// e.g., any 01_*.py or 01-*.ts -> 01_*_policy.json
	if len(nameWithoutExt) >= 2 {
		prefix := nameWithoutExt[0:2]
		if prefix >= "01" && prefix <= "99" {
			policiesDir := filepath.Join(dir, "policies")
			if entries, err := ioutil.ReadDir(policiesDir); err == nil {
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), "_policy.json") {
						return filepath.Join(policiesDir, entry.Name())
					}
				}
			}
		}
	}

	return ""
}

// generateNetworkPolicy creates a policy JSON file with network rules from allowed hosts.
// If an existing policy file is provided, it merges the network rules into it.
func generateNetworkPolicy(allowedHosts []string, existingPolicy string) (string, error) {
	// Build the policy structure
	policy := make(map[string]interface{})

	// If there's an existing policy, load and merge
	if existingPolicy != "" {
		data, err := ioutil.ReadFile(existingPolicy)
		if err == nil {
			json.Unmarshal(data, &policy)
		}
	}

	// Build network rules
	networkRules := make(map[string]interface{})

	// DNS rules - allow resolution for all allowed hosts
	dnsRules := []map[string]interface{}{}
	for _, host := range allowedHosts {
		// Extract hostname (strip port if present)
		hostname := host
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			hostname = host[:idx]
		}
		dnsRules = append(dnsRules, map[string]interface{}{
			"pattern": hostname,
			"allow":   true,
		})
	}
	networkRules["dns"] = dnsRules

	// Connect rules - allow connection to all allowed host:port
	connectRules := []map[string]interface{}{}
	for _, host := range allowedHosts {
		connectRules = append(connectRules, map[string]interface{}{
			"pattern": host,
			"allow":   true,
		})
	}
	networkRules["connect"] = connectRules

	// Default deny for everything else
	networkRules["default_deny"] = true

	policy["network"] = networkRules

	// Write to temp file
	tmpFile, err := ioutil.TempFile("", "ak-policy-*.json")
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	tmpFile.Close()
	return tmpFile.Name(), nil
}

// bundleTree recursively bundles a directory tree, skipping problematic entries
func bundleTree(rootPath, dir, indent string, manifest *bytes.Buffer) error {
	entries, err := ioutil.ReadDir(filepath.Join(rootPath, dir))
	if err != nil {
		return nil // Skip unreadable directories
	}

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(rootPath, dir, name)
		relPath := filepath.Join(dir, name)

		// Skip hidden files and pycache
		if strings.HasPrefix(name, ".") || name == "__pycache__" {
			continue
		}

		if entry.IsDir() {
			// Skip dangerous or unnecessary directories
			if name == "tests" || name == "test" || name == "__phello__" {
				continue
			}
			manifest.WriteString(indent + name + ":(children:(\n")
			bundleTree(rootPath, relPath, indent+"  ", manifest)
			manifest.WriteString(indent + "))\n")
		} else {
			// Verify file exists before including (symlinks might be broken)
			if _, err := os.Stat(fullPath); err == nil {
				manifest.WriteString(indent + name + ":(contents:(host:" + fullPath + "))\n")
			}
		}
	}

	return nil
}

func createImage(imagePath, appPath string, kernelPath string, config *Config, verbose bool) error {
	// Build manifest in Nanos tuple format with proper spacing
	var manifest bytes.Buffer

	// Convert to absolute path for manifest
	absAppPath, err := filepath.Abs(appPath)
	if err != nil {
		return fmt.Errorf("cannot get absolute path: %v", err)
	}

	// Auto-detect program based on app type
	appType := detectAppType(appPath)
	program := "/bin/python3" // default
	appFileName := "main.py"   // default

	switch appType {
	case "node":
		program = "/bin/node"
		appFileName = "main.js" // Use .js for Node.js even if input is .ts
	case "python":
		program = "/bin/python3"
		appFileName = "main.py"
	}

	// Allow override
	if config.Program != "" {
		program = config.Program
	}

	// Build children section with explicit Alpine bundles
	manifest.WriteString("(\n    children:(\n")

	// App file
	manifest.WriteString("        " + appFileName + ":(contents:(host:" + absAppPath + "))\n")

	// Bundle /bin directory (Python, Node.js, shell, etc.)
	pythonRoot := "/tmp/nanos-root"

	// Verify pythonRoot exists
	if _, err := os.Stat(pythonRoot); err != nil {
		return fmt.Errorf("pythonRoot not found: %s (build with Docker to populate)", pythonRoot)
	}

	manifest.WriteString("        bin:(children:(\n")
	if _, err := os.Stat(pythonRoot + "/bin/python3.11"); err == nil {
		manifest.WriteString("            python3.11:(contents:(host:" + pythonRoot + "/bin/python3.11))\n")
	}
	if _, err := os.Stat(pythonRoot + "/bin/python3"); err == nil {
		manifest.WriteString("            python3:(contents:(host:" + pythonRoot + "/bin/python3))\n")
	}
	// Include Node.js if available
	if _, err := os.Stat(pythonRoot + "/bin/node"); err == nil {
		manifest.WriteString("            node:(contents:(host:" + pythonRoot + "/bin/node))\n")
	}
	// Always include busybox (should exist from alpine-rootfs COPY)
	busyboxPath := pythonRoot + "/bin/busybox"
	manifest.WriteString("            busybox:(contents:(host:" + busyboxPath + "))\n")
	// Use Lstat to check for symlinks (doesn't follow the link)
	if _, err := os.Lstat(pythonRoot + "/bin/sh"); err == nil {
		// If sh is a symlink to busybox, include it as a reference to busybox
		manifest.WriteString("            sh:(contents:(host:" + pythonRoot + "/bin/busybox))\n")
	}
	manifest.WriteString("        ))\n")

	// Bundle /lib directory (runtime libraries including libpython, Node.js, and libak)
	manifest.WriteString("        lib:(children:(\n")
	if _, err := os.Stat(pythonRoot + "/lib/libc.musl-x86_64.so.1"); err == nil {
		manifest.WriteString("            libc.musl-x86_64.so.1:(contents:(host:" + pythonRoot + "/lib/libc.musl-x86_64.so.1))\n")
	}
	if _, err := os.Stat(pythonRoot + "/lib/ld-musl-x86_64.so.1"); err == nil {
		manifest.WriteString("            ld-musl-x86_64.so.1:(contents:(host:" + pythonRoot + "/lib/ld-musl-x86_64.so.1))\n")
	}
	// Include libpython (required by Python executable)
	if _, err := os.Stat(pythonRoot + "/usr/lib/libpython3.11.so.1.0"); err == nil {
		manifest.WriteString("            libpython3.11.so.1.0:(contents:(host:" + pythonRoot + "/usr/lib/libpython3.11.so.1.0))\n")
	}
	// Include libv8 if available (required by Node.js)
	if _, err := os.Stat(pythonRoot + "/lib/libv8.so"); err == nil {
		manifest.WriteString("            libv8.so:(contents:(host:" + pythonRoot + "/lib/libv8.so))\n")
	}
	// Include libak.so (Authority Kernel interface)
	if _, err := os.Stat(pythonRoot + "/lib/libak.so"); err == nil {
		manifest.WriteString("            libak.so:(contents:(host:" + pythonRoot + "/lib/libak.so))\n")
	}
	// Include libz.so.1 (required for Python/Node.js compression/SSL)
	if _, err := os.Stat(pythonRoot + "/lib/libz.so.1"); err == nil {
		manifest.WriteString("            libz.so.1:(contents:(host:" + pythonRoot + "/lib/libz.so.1))\n")
	}
	manifest.WriteString("        ))\n")

	// Bundle /etc directory (SSL certificates, resolv.conf, etc.)
	manifest.WriteString("        etc:(children:(\n")
	// Include resolv.conf for DNS
	if _, err := os.Stat(pythonRoot + "/etc/resolv.conf"); err == nil {
		manifest.WriteString("            resolv.conf:(contents:(host:" + pythonRoot + "/etc/resolv.conf))\n")
	}
	// Include SSL certificates
	if _, err := os.Stat(pythonRoot + "/etc/ssl/cert.pem"); err == nil {
		manifest.WriteString("            ssl:(children:(\n")
		manifest.WriteString("                cert.pem:(contents:(host:" + pythonRoot + "/etc/ssl/cert.pem))\n")
		// Bundle ca-certificates.crt which contains all CAs
		if _, err := os.Stat(pythonRoot + "/etc/ssl/certs/ca-certificates.crt"); err == nil {
			manifest.WriteString("                certs:(children:(\n")
			manifest.WriteString("                    ca-certificates.crt:(contents:(host:" + pythonRoot + "/etc/ssl/certs/ca-certificates.crt))\n")
			manifest.WriteString("                ))\n")
		}
		manifest.WriteString("            ))\n")
	}
	manifest.WriteString("        ))\n")

	// Include Authority Kernel policy file at /ak/policy.json
	// Either use explicit policy file or generate from --allow-host flags
	policyPath := ""
	if config.Policy != "" {
		absPolicyPath, err := filepath.Abs(config.Policy)
		if err == nil {
			if _, err := os.Stat(absPolicyPath); err == nil {
				policyPath = absPolicyPath
			}
		}
	}

	// Generate network policy from --allow-host / --allow-llm flags
	if config.Network != nil && len(config.Network.AllowedHosts) > 0 {
		generatedPolicy, err := generateNetworkPolicy(config.Network.AllowedHosts, policyPath)
		if err == nil {
			policyPath = generatedPolicy
		}
	}

	if policyPath != "" {
		manifest.WriteString("        ak:(children:(\n")
		manifest.WriteString("            policy.json:(contents:(host:" + policyPath + "))\n")
		manifest.WriteString("        ))\n")
	}

	// Bundle Python stdlib via /usr/lib directory
	manifest.WriteString("        usr:(children:(lib:(children:(\n")
	// Use bundleTree to recursively include Python stdlib, filtering for safe characters
	bundleTree(pythonRoot, "usr/lib", "", &manifest)
	manifest.WriteString("        ))))\n")

	manifest.WriteString("    )\n")

	manifest.WriteString("program:" + program + " ")

	// Enable serial console output
	manifest.WriteString("console:t ")

	// Add command-line arguments - use appFileName (main.py, main.js, etc.)
	// For Python programs, add -u flag for unbuffered output by default
	manifest.WriteString("arguments:[")
	hasScript := false
	hasUnbuffered := false

	// Check if -u flag is already present (Python only)
	for _, arg := range config.Args {
		if arg == "-u" {
			hasUnbuffered = true
			break
		}
	}

	// For Python, add -u if not present
	if strings.Contains(program, "python") && !hasUnbuffered {
		manifest.WriteString("-u ")
	}

	for i, arg := range config.Args {
		if i > 0 || (strings.Contains(program, "python") && !hasUnbuffered) {
			manifest.WriteString(" ")
		}
		// Replace the original script name with the appropriate app file name
		if strings.HasSuffix(arg, ".py") || strings.HasSuffix(arg, ".js") || strings.HasSuffix(arg, ".ts") || strings.HasSuffix(arg, ".mjs") {
			manifest.WriteString(appFileName)
			hasScript = true
		} else {
			manifest.WriteString(arg)
		}
	}
	// If no script file was in args, add the app file name
	if !hasScript {
		manifest.WriteString(" " + appFileName)
	}
	manifest.WriteString("]")

	// Add environment variables - include language-specific paths
	manifest.WriteString(" environment:(")
	// Add default Python environment if running Python
	if strings.Contains(program, "python") {
		// Only add if not already specified in config
		if _, ok := config.Env["PYTHONHOME"]; !ok {
			manifest.WriteString("PYTHONHOME:/usr ")
		}
		if _, ok := config.Env["PYTHONPATH"]; !ok {
			manifest.WriteString("PYTHONPATH:/usr/lib/python3.11 ")
		}
	}
	// Add default Node.js environment if running Node.js
	if strings.Contains(program, "node") {
		// Node.js typically uses node_modules for local packages
		// The app directory will need to be searched for node_modules
		if _, ok := config.Env["NODE_PATH"]; !ok {
			manifest.WriteString("NODE_PATH:/usr/lib/node_modules ")
		}
	}
	// Add LIBAK_PATH for Authority Kernel SDK (for both Python and Node.js)
	if _, ok := config.Env["LIBAK_PATH"]; !ok {
		manifest.WriteString("LIBAK_PATH:/lib/libak.so ")
	}
	// SSL/TLS certificate paths for HTTPS support (LangChain, CrewAI, etc.)
	if _, ok := config.Env["SSL_CERT_FILE"]; !ok {
		manifest.WriteString("SSL_CERT_FILE:/etc/ssl/cert.pem ")
	}
	if _, ok := config.Env["SSL_CERT_DIR"]; !ok {
		manifest.WriteString("SSL_CERT_DIR:/etc/ssl/certs ")
	}
	if _, ok := config.Env["REQUESTS_CA_BUNDLE"]; !ok {
		manifest.WriteString("REQUESTS_CA_BUNDLE:/etc/ssl/cert.pem ")
	}
	// Add user-specified environment variables
	for k, v := range config.Env {
		manifest.WriteString(k + ":" + v + " ")
	}
	manifest.WriteString(")")

	// Add manifest passthrough settings
	if len(config.ManifestPassthrough) > 0 {
		for k, v := range config.ManifestPassthrough {
			manifest.WriteString(" ")
			switch vv := v.(type) {
			case string:
				manifest.WriteString(k + ":" + vv)
			case []interface{}:
				manifest.WriteString(k + ":[")
				for i, item := range vv {
					if i > 0 {
						manifest.WriteString(" ")
					}
					manifest.WriteString(fmt.Sprintf("%v", item))
				}
				manifest.WriteString("]")
			default:
				manifest.WriteString(k + ":" + fmt.Sprintf("%v", v))
			}
		}
	}

	manifest.WriteString(")\n")

	if verbose {
		fmt.Printf("   Manifest:\n%s\n", manifest.String())
	}

	// Find mkfs tool
	mkfsPath := findMkfs()
	if mkfsPath == "" {
		return fmt.Errorf("mkfs tool not found. Build with: make -j$(nproc)")
	}

	if verbose {
		fmt.Printf("   Using mkfs: %s\n", mkfsPath)
	}

	// Find bootloader
	bootloaderPath := findBootloader()
	if bootloaderPath == "" {
		// For now, continue without bootloader - output may still work
		if verbose {
			fmt.Printf("   ⚠️  Bootloader not found (output may not display)\n")
		}
	} else {
		if verbose {
			fmt.Printf("   Using bootloader: %s\n", bootloaderPath)
		}
	}

	// Run mkfs with manifest from stdin
	// Use -b flag for bootloader (if found) and -k flag for kernel image
	mkfsArgs := []string{"-k", kernelPath}
	if bootloaderPath != "" {
		mkfsArgs = append([]string{"-b", bootloaderPath}, mkfsArgs...)
	}

	// NOTE: Do NOT use -r flag when explicit bundling is in manifest
	// The explicit children entries in the manifest provide all necessary files

	mkfsArgs = append(mkfsArgs, imagePath)

	cmd := exec.Command(mkfsPath, mkfsArgs...)
	cmd.Stdin = &manifest

	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Printf("   mkfs args: %v\n", mkfsArgs)
	} else {
		// Capture output for error reporting
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			output := stderr.String()
			if output == "" {
				output = stdout.String()
			}
			return fmt.Errorf("mkfs failed: %v\nOutput: %s", err, output)
		}
		return nil
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mkfs failed: %v", err)
	}

	return nil
}

func launchQEMU(kernelPath, imagePath string, config *Config, memory int, verbose bool) error {
	// Build QEMU command for Nanos bootloader + kernel
	cmd := exec.Command("qemu-system-x86_64")

	args := []string{
		"-m", fmt.Sprintf("%dM", memory),
		"-display", "none",
		"-serial", "stdio",
		"-hda", imagePath,
		// Enable user-mode networking with virtio NIC and DNS
		"-netdev", "user,id=n0,hostfwd=tcp::8080-:80",
		"-device", "virtio-net-pci,netdev=n0",
	}

	if verbose {
		fmt.Printf("🔧 QEMU Command:\n")
		fmt.Printf("   qemu-system-x86_64 %s\n\n", fmt.Sprint(args))
	}

	cmd.Args = append(cmd.Args, args...)

	// Run QEMU with output to stdout
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		// QEMU may exit with specific codes, which is OK
		if _, ok := err.(*exec.ExitError); ok {
			return nil // QEMU exited normally
		}
		return err
	}

	return nil
}

// ensureRootfs checks if the Alpine rootfs and kernel exist, extracts from Docker if not
func ensureRootfs(verbose bool) error {
	pythonRoot := "/tmp/nanos-root"
	pythonBin := filepath.Join(pythonRoot, "bin", "python3.11")
	kernelCache := "/tmp/nanos-kernel"
	kernelImg := filepath.Join(kernelCache, "kernel.img")

	// Check if both rootfs and kernel already exist
	_, rootfsErr := os.Stat(pythonBin)
	_, kernelErr := os.Stat(kernelImg)
	if rootfsErr == nil && kernelErr == nil {
		return nil // Already set up
	}

	fmt.Printf("📦 Setting up Nanos environment (one-time setup)...\n")

	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found - required for initial setup")
	}

	// Check if nanos-python image exists
	checkImg := exec.Command("docker", "image", "inspect", "nanos-python")
	if err := checkImg.Run(); err != nil {
		fmt.Printf("   Building nanos-python Docker image...\n")
		// Find Dockerfile.build - look in common locations
		dockerfilePath := ""
		candidates := []string{
			"Dockerfile.build",
			"../Dockerfile.build",
			"../../Dockerfile.build",
		}
		// Also try relative to executable
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			candidates = append(candidates,
				filepath.Join(exeDir, "..", "..", "Dockerfile.build"),
				filepath.Join(exeDir, "Dockerfile.build"),
			)
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				dockerfilePath = p
				break
			}
		}
		if dockerfilePath == "" {
			return fmt.Errorf("Dockerfile.build not found - run from nanos directory")
		}

		// Get build context directory
		buildContext := filepath.Dir(dockerfilePath)
		if buildContext == "." || buildContext == "" {
			buildContext, _ = os.Getwd()
		}

		buildCmd := exec.Command("docker", "build", "-f", dockerfilePath, "-t", "nanos-python", buildContext)
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build Docker image: %v", err)
		}
	}

	// Remove old container if exists
	exec.Command("docker", "rm", "-f", "nanos-extract").Run()

	// Create container
	createCmd := exec.Command("docker", "create", "--platform", "linux/amd64", "--name", "nanos-extract", "nanos-python")
	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}

	// Extract rootfs if needed
	if rootfsErr != nil {
		fmt.Printf("   Extracting rootfs to %s...\n", pythonRoot)
		os.MkdirAll(pythonRoot, 0755)
		copyCmd := exec.Command("docker", "cp", "nanos-extract:/tmp/nanos-root/.", pythonRoot)
		if err := copyCmd.Run(); err != nil {
			exec.Command("docker", "rm", "-f", "nanos-extract").Run()
			return fmt.Errorf("failed to extract rootfs: %v", err)
		}
	}

	// Extract kernel if needed
	if kernelErr != nil {
		fmt.Printf("   Extracting kernel to %s...\n", kernelCache)
		os.MkdirAll(kernelCache, 0755)

		// Extract kernel.img
		copyKernel := exec.Command("docker", "cp", "nanos-extract:/nanos/output/platform/pc/bin/kernel.img", kernelImg)
		if err := copyKernel.Run(); err != nil {
			exec.Command("docker", "rm", "-f", "nanos-extract").Run()
			return fmt.Errorf("failed to extract kernel: %v", err)
		}

		// Extract bootloader
		copyBoot := exec.Command("docker", "cp", "nanos-extract:/nanos/output/platform/pc/boot/boot.img", filepath.Join(kernelCache, "boot.img"))
		copyBoot.Run() // Ignore error - bootloader is optional

		// Extract mkfs (Linux version for reference, though we use native)
		copyMkfs := exec.Command("docker", "cp", "nanos-extract:/nanos/output/tools/bin/mkfs", filepath.Join(kernelCache, "mkfs-linux"))
		copyMkfs.Run() // Ignore error
	}

	// Cleanup container
	exec.Command("docker", "rm", "-f", "nanos-extract").Run()

	fmt.Printf("   ✅ Environment ready\n\n")
	return nil
}

// runWithDocker runs the app using Docker (for macOS) - kept for fallback
func runWithDocker(appFile, configFile string, memory int, verbose bool) {
	// Get absolute path of app file
	absAppFile, err := filepath.Abs(appFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path: %v\n", err)
		os.Exit(1)
	}

	// Get the directory containing the app for mounting
	appDir := filepath.Dir(absAppFile)
	appName := filepath.Base(absAppFile)

	if verbose {
		fmt.Printf("🐳 Running via Docker (macOS detected)\n")
		fmt.Printf("   App: %s\n", absAppFile)
		fmt.Printf("   Memory: %dMB\n", memory)
		fmt.Printf("\n")
	}

	// Build docker run command
	dockerArgs := []string{
		"run", "--rm",
		"--platform", "linux/amd64",
		"-v", fmt.Sprintf("%s:/app:ro", appDir),
	}

	// Mount config file if it exists and is not default
	if configFile != "config.json" {
		absConfigFile, err := filepath.Abs(configFile)
		if err == nil {
			if _, err := os.Stat(absConfigFile); err == nil {
				dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/nanos/config.json:ro", absConfigFile))
			}
		}
	} else if _, err := os.Stat(configFile); err == nil {
		absConfigFile, _ := filepath.Abs(configFile)
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/nanos/config.json:ro", absConfigFile))
	}

	dockerArgs = append(dockerArgs, "nanos-python", "bash", "-c",
		fmt.Sprintf("cd /nanos && cp /app/%s /tmp/app.py && tools/minops/minops run /tmp/app.py -m %d %s",
			appName, memory, func() string {
				if verbose {
					return "-v"
				}
				return ""
			}()))

	if verbose {
		fmt.Printf("🐳 Docker command: docker %s\n\n", strings.Join(dockerArgs, " "))
	}

	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error running Docker: %v\n", err)
		os.Exit(1)
	}
}

// ToolManifest represents a deployed tool
type ToolManifest struct {
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	Policy      string            `json:"policy"`
	Signature   string            `json:"signature,omitempty"`
	Capabilities []string         `json:"capabilities,omitempty"`
	DeployedAt  string            `json:"deployed_at"`
	Hash        string            `json:"hash"`
}

// ToolRegistry stores deployed tools
type ToolRegistry struct {
	Tools   []ToolManifest `json:"tools"`
	Version string         `json:"version"`
}

func getToolRegistryPath() string {
	// Store in user's config directory
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/ak-tools.json"
	}
	return filepath.Join(home, ".authority", "tools.json")
}

func loadToolRegistry() (*ToolRegistry, error) {
	path := getToolRegistryPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &ToolRegistry{Version: "1.0", Tools: []ToolManifest{}}, nil
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var registry ToolRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, err
	}

	return &registry, nil
}

func saveToolRegistry(registry *ToolRegistry) error {
	path := getToolRegistryPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, data, 0644)
}

func deployTool(args []string) {
	var (
		toolFile   string
		policyFile string
		toolName   string
		signature  string
		verbose    bool
	)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-v", "-verbose":
			verbose = true
		case "-p", "--policy":
			if i+1 < len(args) {
				policyFile = args[i+1]
				i++
			}
		case "-n", "--name":
			if i+1 < len(args) {
				toolName = args[i+1]
				i++
			}
		case "--signature":
			if i+1 < len(args) {
				signature = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(arg, "-") && toolFile == "" {
				toolFile = arg
			}
		}
	}

	if toolFile == "" {
		fmt.Fprintf(os.Stderr, "Error: No tool file specified\n")
		fmt.Fprintf(os.Stderr, "Usage: minops deploy <tool.wasm> [-p policy.json] [-n name]\n")
		os.Exit(1)
	}

	// Check tool file exists
	if _, err := os.Stat(toolFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Tool file not found: %s\n", toolFile)
		os.Exit(1)
	}

	// Default tool name from filename
	if toolName == "" {
		toolName = strings.TrimSuffix(filepath.Base(toolFile), filepath.Ext(toolFile))
	}

	// Read and hash the tool file
	toolData, err := ioutil.ReadFile(toolFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading tool file: %v\n", err)
		os.Exit(1)
	}

	// Simple hash (in production, use SHA-256)
	hash := fmt.Sprintf("%x", len(toolData))

	// Copy tool to registry directory
	registryDir := filepath.Dir(getToolRegistryPath())
	toolsDir := filepath.Join(registryDir, "wasm")
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating tools directory: %v\n", err)
		os.Exit(1)
	}

	destPath := filepath.Join(toolsDir, toolName+".wasm")
	if err := ioutil.WriteFile(destPath, toolData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error copying tool: %v\n", err)
		os.Exit(1)
	}

	// Copy policy if provided
	var policyPath string
	if policyFile != "" {
		policyData, err := ioutil.ReadFile(policyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy file: %v\n", err)
			os.Exit(1)
		}
		policyPath = filepath.Join(toolsDir, toolName+"_policy.json")
		if err := ioutil.WriteFile(policyPath, policyData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error copying policy: %v\n", err)
			os.Exit(1)
		}
	}

	// Load registry and add tool
	registry, err := loadToolRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading tool registry: %v\n", err)
		os.Exit(1)
	}

	// Check if tool already exists and update
	found := false
	for i, t := range registry.Tools {
		if t.Name == toolName {
			registry.Tools[i] = ToolManifest{
				Name:       toolName,
				Path:       destPath,
				Policy:     policyPath,
				Signature:  signature,
				DeployedAt: fmt.Sprintf("%d", os.Getpid()), // Placeholder timestamp
				Hash:       hash,
			}
			found = true
			break
		}
	}

	if !found {
		registry.Tools = append(registry.Tools, ToolManifest{
			Name:       toolName,
			Path:       destPath,
			Policy:     policyPath,
			Signature:  signature,
			DeployedAt: fmt.Sprintf("%d", os.Getpid()),
			Hash:       hash,
		})
	}

	if err := saveToolRegistry(registry); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving tool registry: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Tool deployed:\n")
		fmt.Printf("  Name: %s\n", toolName)
		fmt.Printf("  Path: %s\n", destPath)
		fmt.Printf("  Policy: %s\n", policyPath)
		fmt.Printf("  Hash: %s\n", hash)
	} else {
		fmt.Printf("✅ Deployed tool: %s\n", toolName)
	}
}

func listTools(args []string) {
	registry, err := loadToolRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading tool registry: %v\n", err)
		os.Exit(1)
	}

	if len(registry.Tools) == 0 {
		fmt.Println("No tools deployed")
		fmt.Println("\nDeploy a tool with: minops deploy <tool.wasm> -p policy.json")
		return
	}

	fmt.Printf("Deployed Tools (%d):\n", len(registry.Tools))
	fmt.Println(strings.Repeat("-", 60))
	for _, tool := range registry.Tools {
		fmt.Printf("  %-20s %s\n", tool.Name, tool.Path)
		if tool.Policy != "" {
			fmt.Printf("    ├─ Policy: %s\n", tool.Policy)
		}
		if tool.Hash != "" {
			fmt.Printf("    └─ Hash: %s\n", tool.Hash)
		}
	}
}

func runProxy(args []string) {
	var (
		socketPath  = "/tmp/akproxy.sock"
		llmProvider = "openai"
		llmEndpoint = ""
		llmAPIKey   = ""
		allowedDirs = "/tmp"
	)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-s", "--socket":
			if i+1 < len(args) {
				socketPath = args[i+1]
				i++
			}
		case "--llm-provider":
			if i+1 < len(args) {
				llmProvider = args[i+1]
				i++
			}
		case "--llm-endpoint":
			if i+1 < len(args) {
				llmEndpoint = args[i+1]
				i++
			}
		case "--llm-api-key":
			if i+1 < len(args) {
				llmAPIKey = args[i+1]
				i++
			}
		case "--allowed-dirs":
			if i+1 < len(args) {
				allowedDirs = args[i+1]
				i++
			}
		}
	}

	// Find akproxy binary
	execDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	akproxyPath := filepath.Join(execDir, "akproxy")

	if _, err := os.Stat(akproxyPath); os.IsNotExist(err) {
		// Try in tools/akproxy
		akproxyPath = filepath.Join(execDir, "..", "akproxy", "akproxy")
		if _, err := os.Stat(akproxyPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: akproxy binary not found\n")
			fmt.Fprintf(os.Stderr, "Build it with: cd tools/akproxy && go build\n")
			os.Exit(1)
		}
	}

	// Build akproxy command
	proxyArgs := []string{
		"-socket", socketPath,
		"-llm-provider", llmProvider,
		"-allowed-dirs", allowedDirs,
	}

	if llmEndpoint != "" {
		proxyArgs = append(proxyArgs, "-llm-endpoint", llmEndpoint)
	}

	if llmAPIKey != "" {
		proxyArgs = append(proxyArgs, "-llm-api-key", llmAPIKey)
	}

	fmt.Printf("🚀 Starting Authority Kernel Proxy...\n")
	fmt.Printf("   Socket: %s\n", socketPath)
	fmt.Printf("   LLM Provider: %s\n", llmProvider)
	fmt.Printf("   Allowed Dirs: %s\n", allowedDirs)

	cmd := exec.Command(akproxyPath, proxyArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running akproxy: %v\n", err)
		os.Exit(1)
	}
}
