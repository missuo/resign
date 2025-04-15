package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"howett.net/plist"
)

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{{.IpaURL}}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{{.BundleID}}</string>
                <key>bundle-version</key>
                <string>1</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>{{.AppName}}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>`

var (
	baseURL      string       // Base URL for download links, configurable via command line args or env vars
	outputDir    = "./output" // Root directory for storing output files
	port         string       // Server listening port
	ipaCache     = make(map[string]IPAInfo)
	ipaCacheLock sync.RWMutex
)

// IPAInfo stores information about analyzed IPA files
type IPAInfo struct {
	OriginalURL string
	UUID        string
	BundleID    string
	AppName     string
	UploadedAt  time.Time
}

func init() {
	// Define command line flags
	flag.StringVar(&baseURL, "base-url", "http://localhost:8080", "Base URL for generated download links")
	flag.StringVar(&port, "port", "8080", "Port to listen on")

	// Parse command line arguments
	flag.Parse()

	// If base URL is not set via command line, try environment variable
	if baseURL == "" {
		baseURL = os.Getenv("BASE_URL")
		// If env var is also not set, use default value
		if baseURL == "" {
			fmt.Println("Warning: BASE_URL not set, using default value")
			baseURL = fmt.Sprintf("http://localhost:%s", port)
		}
	}

	// Ensure baseURL doesn't end with a slash
	baseURL = strings.TrimRight(baseURL, "/")

	// Print configuration info
	fmt.Printf("Using BASE_URL: %s\n", baseURL)
	fmt.Printf("Using PORT: %s\n", port)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(cors.Default())

	r.POST("/resign", resignHandler)
	r.POST("/analyze", analyzeIPAHandler) // New endpoint for analyzing IPA files
	r.GET("/download/:uuid/:filename", downloadHandler)

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		panic(err)
	}

	// Start the server
	fmt.Printf("Server starting on port %s...\n", port)
	r.Run(":" + port)
}

// Download a file from URL and save it to the specified filepath
func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// Extract Info.plist from IPA file and parse it
func extractIPAInfo(ipaPath string) (string, string, error) {
	reader, err := zip.OpenReader(ipaPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open IPA file: %v", err)
	}
	defer reader.Close()

	var infoPlistFile *zip.File
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".app/Info.plist") {
			infoPlistFile = file
			break
		}
	}

	if infoPlistFile == nil {
		return "", "", fmt.Errorf("info.plist not found in IPA")
	}

	// Open the plist file
	rc, err := infoPlistFile.Open()
	if err != nil {
		return "", "", fmt.Errorf("failed to open Info.plist: %v", err)
	}
	defer rc.Close()

	// Read the plist content
	plistData, err := io.ReadAll(rc)
	if err != nil {
		return "", "", fmt.Errorf("failed to read Info.plist: %v", err)
	}

	// Parse the plist
	var plistObj map[string]interface{}
	if _, err := plist.Unmarshal(plistData, &plistObj); err != nil {
		return "", "", fmt.Errorf("failed to parse Info.plist: %v", err)
	}

	// Extract bundle ID and app name
	bundleID, ok := plistObj["CFBundleIdentifier"].(string)
	if !ok {
		return "", "", fmt.Errorf("CFBundleIdentifier not found or not a string")
	}

	appName, ok := plistObj["CFBundleDisplayName"].(string)
	if !ok {
		// Try CFBundleName as fallback
		appName, ok = plistObj["CFBundleName"].(string)
		if !ok {
			appName = "Unknown App"
		}
	}

	return bundleID, appName, nil
}

// Handler for the new analyze endpoint
func analyzeIPAHandler(c *gin.Context) {
	// Get IPA download URL from form data
	ipaURL := c.PostForm("ipa_url")
	if ipaURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ipa_url parameter"})
		return
	}

	// Check if this URL has already been analyzed
	ipaCacheLock.RLock()
	for _, info := range ipaCache {
		if info.OriginalURL == ipaURL {
			ipaCacheLock.RUnlock()
			c.JSON(http.StatusOK, gin.H{
				"uuid":       info.UUID,
				"bundle_id":  info.BundleID,
				"app_name":   info.AppName,
				"source_url": fmt.Sprintf("%s/download/%s/source.ipa", baseURL, info.UUID),
				"analyzed":   true,
			})
			return
		}
	}
	ipaCacheLock.RUnlock()

	// Generate a UUID for this IPA
	uuidStr := uuid.New().String()

	// Create directory for this IPA
	workDir := filepath.Join(outputDir, uuidStr)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create directory"})
		return
	}

	// Path for source IPA
	ipaPath := filepath.Join(workDir, "source.ipa")

	// Download the IPA file
	if err := downloadFile(ipaURL, ipaPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download IPA file: " + err.Error()})
		return
	}

	// Extract bundle ID and app name
	bundleID, appName, err := extractIPAInfo(ipaPath)
	if err != nil {
		// If extraction fails, delete the downloaded file
		os.RemoveAll(workDir)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to extract IPA info: " + err.Error()})
		return
	}

	// Store the IPA info in cache
	ipaCacheLock.Lock()
	ipaCache[uuidStr] = IPAInfo{
		OriginalURL: ipaURL,
		UUID:        uuidStr,
		BundleID:    bundleID,
		AppName:     appName,
		UploadedAt:  time.Now(),
	}
	ipaCacheLock.Unlock()

	// Return the UUID and extracted info
	c.JSON(http.StatusOK, gin.H{
		"uuid":       uuidStr,
		"bundle_id":  bundleID,
		"app_name":   appName,
		"source_url": fmt.Sprintf("%s/download/%s/source.ipa", baseURL, uuidStr),
		"analyzed":   true,
	})
}

// Handler for downloading files
func downloadHandler(c *gin.Context) {
	uuid := c.Param("uuid")
	filename := c.Param("filename")
	filePath := filepath.Join(outputDir, uuid, filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Set appropriate Content-Type header
	if strings.HasSuffix(filename, ".ipa") {
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	} else if strings.HasSuffix(filename, ".plist") {
		c.Header("Content-Type", "application/xml")
	}

	c.File(filePath)
}

// Modified resign handler that uses UUID directories
func resignHandler(c *gin.Context) {
	// Get UUID for the IPA to resign
	var uuidStr string
	var sourceIpaPath string
	var bundleID, appName string
	var workDir string

	ipaUUID := c.PostForm("ipa_uuid")
	ipaURL := c.PostForm("ipa_url")

	if ipaUUID != "" {
		// Use existing analyzed IPA if UUID is provided
		ipaCacheLock.RLock()
		info, exists := ipaCache[ipaUUID]
		ipaCacheLock.RUnlock()

		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ipa_uuid, IPA not found"})
			return
		}

		uuidStr = ipaUUID
		workDir = filepath.Join(outputDir, uuidStr)
		sourceIpaPath = filepath.Join(workDir, "source.ipa")

		// Use the stored bundle ID and app name if not provided
		providedBundleID := c.PostForm("bundle_id")
		providedAppName := c.PostForm("app_name")

		if providedBundleID != "" {
			bundleID = providedBundleID
		} else {
			bundleID = info.BundleID
		}

		if providedAppName != "" {
			appName = providedAppName
		} else {
			appName = info.AppName
		}

	} else if ipaURL != "" {
		// Create a new UUID for this IPA
		uuidStr = uuid.New().String()
		workDir = filepath.Join(outputDir, uuidStr)

		// Create directory for this IPA
		if err := os.MkdirAll(workDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create directory"})
			return
		}

		// Download the IPA file
		sourceIpaPath = filepath.Join(workDir, "source.ipa")
		if err := downloadFile(ipaURL, sourceIpaPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download IPA file"})
			os.RemoveAll(workDir)
			return
		}

		// Get bundle ID and app name from parameters
		bundleID = c.PostForm("bundle_id")
		appName = c.PostForm("app_name")

		// If not provided, try to extract from IPA
		if bundleID == "" || appName == "" {
			extractedBundleID, extractedAppName, err := extractIPAInfo(sourceIpaPath)
			if err == nil {
				if bundleID == "" {
					bundleID = extractedBundleID
				}
				if appName == "" {
					appName = extractedAppName
				}
			}
		}

		// Store the IPA info in cache
		ipaCacheLock.Lock()
		ipaCache[uuidStr] = IPAInfo{
			OriginalURL: ipaURL,
			UUID:        uuidStr,
			BundleID:    bundleID,
			AppName:     appName,
			UploadedAt:  time.Now(),
		}
		ipaCacheLock.Unlock()
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either ipa_url or ipa_uuid must be provided"})
		return
	}

	// Handle uploaded p12 certificate
	p12, err := c.FormFile("p12")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing p12 file"})
		return
	}
	p12Path := filepath.Join(workDir, "cert.p12")
	if err := c.SaveUploadedFile(p12, p12Path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save p12 file"})
		return
	}

	// Handle uploaded mobile provision profile
	mobileprovision, err := c.FormFile("mobileprovision")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing mobileprovision file"})
		return
	}
	mobileprovisionPath := filepath.Join(workDir, "profile.mobileprovision")
	if err := c.SaveUploadedFile(mobileprovision, mobileprovisionPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save mobileprovision file"})
		return
	}

	// Get p12 password
	p12Password := c.PostForm("p12_password")
	if p12Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing p12_password parameter"})
		return
	}

	// Verify we have bundle ID and app name
	if bundleID == "" || appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bundle ID and App Name must be provided"})
		return
	}

	// Fixed output filename
	outputPath := filepath.Join(workDir, "resigned.ipa")

	// Execute the signing command
	cmd := exec.Command(
		"zsign",
		"-k", p12Path,
		"-m", mobileprovisionPath,
		"-p", p12Password,
		"-b", bundleID,
		"-n", appName,
		"-o", outputPath,
		"-z", "9",
		sourceIpaPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Signing failed", "output": string(output)})
		return
	}

	// Verify output file was generated
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Output file was not generated"})
		return
	}

	// Generate plist file with fixed name
	plistPath := filepath.Join(workDir, "manifest.plist")
	ipaDownloadURL := fmt.Sprintf("%s/download/%s/resigned.ipa", baseURL, uuidStr)
	plistContent := generatePlist(ipaDownloadURL, bundleID, appName)

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create plist file"})
		return
	}

	// Generate URLs with consistent paths
	plistURL := fmt.Sprintf("%s/download/%s/manifest.plist", baseURL, uuidStr)
	sourceURL := fmt.Sprintf("%s/download/%s/source.ipa", baseURL, uuidStr)
	resignedURL := fmt.Sprintf("%s/download/%s/resigned.ipa", baseURL, uuidStr)

	// Return the download URLs
	c.JSON(http.StatusOK, gin.H{
		"uuid":       uuidStr,
		"plist_url":  plistURL,
		"source_url": sourceURL,
		"ipa_url":    resignedURL,
		"bundle_id":  bundleID,
		"app_name":   appName,
	})
}

// Generate plist file content using the template
func generatePlist(ipaURL, bundleID, appName string) string {
	tmpl, err := template.New("plist").Parse(plistTemplate)
	if err != nil {
		return ""
	}

	var result strings.Builder
	err = tmpl.Execute(&result, struct {
		IpaURL   string
		BundleID string
		AppName  string
	}{
		IpaURL:   ipaURL,
		BundleID: bundleID,
		AppName:  appName,
	})

	if err != nil {
		return ""
	}

	return result.String()
}
