# IPA-Resign

A RESTful API service for iOS IPA file analysis and re-signing. This service provides an alternative to Esign and Universal-sign tools.

## Features

- Analyze IPA files to extract bundle ID and app name
- Re-sign IPA files with custom certificates and provisioning profiles
- Generate installation manifest files for iOS OTA installation
- Consistent UUID-based storage of files
- Caching of previously analyzed IPAs

## Prerequisites

- [zsign](https://github.com/zhlynn/zsign) must be installed on your deployment server
- Go 1.16 or later

## Installation

```bash
git clone https://github.com/yourusername/ipa-resign.git
cd ipa-resign
go mod download
go build .
```

## Usage

```bash
# Basic usage with default settings
./ipa-resign

# Custom base URL and port
./ipa-resign --base-url=https://example.com --port=9900

# Using environment variables
export BASE_URL=https://example.com
./ipa-resign --port=9900
```

## API Endpoints

### Analyze IPA

```
POST /analyze
```

Parameters:
- `ipa_url`: Direct download URL to the IPA file

Response:
```json
{
  "uuid": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "bundle_id": "com.example.app",
  "app_name": "Example App",
  "source_url": "https://example.com/download/6ba7b810-9dad-11d1-80b4-00c04fd430c8/source.ipa",
  "analyzed": true
}
```

### Re-sign IPA

```
POST /resign
```

Parameters:
- Either `ipa_uuid` (from previous analysis) or `ipa_url` (direct download link)
- `p12`: Upload your signing certificate (multipart/form-data)
- `mobileprovision`: Upload your provisioning profile (multipart/form-data)
- `p12_password`: Password for the p12 certificate
- `bundle_id`: (Optional) Custom bundle ID for the resigned app
- `app_name`: (Optional) Custom app name for the resigned app

Response:
```json
{
  "uuid": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "plist_url": "https://example.com/download/6ba7b810-9dad-11d1-80b4-00c04fd430c8/manifest.plist",
  "source_url": "https://example.com/download/6ba7b810-9dad-11d1-80b4-00c04fd430c8/source.ipa",
  "ipa_url": "https://example.com/download/6ba7b810-9dad-11d1-80b4-00c04fd430c8/resigned.ipa",
  "bundle_id": "com.example.app",
  "app_name": "Example App"
}
```

### Download Files

```
GET /download/:uuid/:filename
```

Supported filenames:
- `source.ipa`: Original IPA file
- `resigned.ipa`: Re-signed IPA file
- `manifest.plist`: Installation manifest for iOS OTA installation

## OTA Installation

After re-signing an IPA, you can install it on iOS devices using the Safari browser with the following URL format:

```
itms-services://?action=download-manifest&url=https://example.com/download/UUID/manifest.plist
```

## Demo

A demo service is available at [https://sign.missuo.me](https://sign.missuo.me)

![demo](./screenshots/demo.png)

**Note**: The front-end interface is not open source at this time. When using the service, all fields must be completed, and direct IPA file uploads are not supported. You must provide correct and complete download links.

## Project Structure

```
ipa-resign/
├── main.go          # Main application code
├── output/          # Generated files directory
│   └── [UUID]/      # Unique directories for each IPA
│       ├── source.ipa
│       ├── resigned.ipa
│       ├── manifest.plist
│       ├── cert.p12
│       └── profile.mobileprovision
└── screenshots/     # Screenshots for documentation
```

## License

[BSD-3-Clause](./LICENSE)