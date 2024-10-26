package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
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
	baseURL   string       // Base URL for download links, configurable via command line args or env vars
	outputDir = "./output" // Root directory for storing output files
	port      string       // Server listening port
)

func init() {
	// Define command line flags
	flag.StringVar(&baseURL, "base-url", "", "Base URL for generated download links")
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
	r.GET("/download/:folder/:filename", downloadHandler)

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		panic(err)
	}

	// Start the server
	fmt.Printf("Server starting on port %s...\n", port)
	r.Run(":" + port)
}

// Generate a random string of specified length for use in folder names
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
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

// Handler for the resign endpoint
func resignHandler(c *gin.Context) {
	// Generate a unique random folder name
	randomFolder := generateRandomString(16)
	workDir := filepath.Join(outputDir, randomFolder)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create work directory"})
		return
	}

	// Get IPA download URL from form data
	ipaURL := c.PostForm("ipa_url")
	if ipaURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ipa_url parameter"})
		return
	}

	// Download the IPA file
	sourceIpaPath := filepath.Join(workDir, "source.ipa")
	if err := downloadFile(ipaURL, sourceIpaPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download IPA file"})
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

	// Get other required parameters
	p12Password := c.PostForm("p12_password")
	bundleID := c.PostForm("bundle_id")
	appName := c.PostForm("app_name")

	if p12Password == "" || bundleID == "" || appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}

	// Generate output filename with timestamp
	timestamp := time.Now().UnixNano()
	outputName := fmt.Sprintf("resigned_%d.ipa", timestamp)
	outputPath := filepath.Join(workDir, outputName)

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

	// Generate plist file
	plistName := fmt.Sprintf("manifest_%d.plist", timestamp)
	plistPath := filepath.Join(workDir, plistName)
	ipaDownloadURL := fmt.Sprintf("%s/download/%s/%s", baseURL, randomFolder, outputName)
	plistContent := generatePlist(ipaDownloadURL, bundleID, appName)

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create plist file"})
		return
	}

	plistURL := fmt.Sprintf("%s/download/%s/%s", baseURL, randomFolder, plistName)

	// Return the download URLs
	c.JSON(http.StatusOK, gin.H{
		"plist_url": plistURL,
		"ipa_url":   ipaDownloadURL,
	})
}

// Handler for downloading files
func downloadHandler(c *gin.Context) {
	folder := c.Param("folder")
	filename := c.Param("filename")
	filePath := filepath.Join(outputDir, folder, filename)

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
