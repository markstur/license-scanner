// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/IBM/license-scanner/configurer"

	"github.com/spf13/viper"
)

type Resources struct {
	config *viper.Viper
}

func NewResources(cfg *viper.Viper) *Resources {
	return &Resources{cfg}
}

type resourceReader interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
}

type ReaderReader struct{}

var (
	//go:embed spdx/*/template spdx/*/precheck spdx/*/json custom/*/license_patterns
	embeddedFS        embed.FS
	_, thisFile, _, _                = runtime.Caller(0) // Dirs/files are relative to this file
	thisDir                          = filepath.Dir(thisFile)
	_                 resourceReader = ReaderReader{} // static check for implements interface
)

func (rr ReaderReader) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (rr ReaderReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func getResourcesPath(cfg *viper.Viper, pathFlag string, embeddedFlag string) string {
	pathValue := cfg.GetString(pathFlag)
	if pathValue == "" {
		pathValue = path.Join(embeddedFlag, cfg.GetString(embeddedFlag))
		return pathValue
	}
	return pathValue
}

// getResourcesWritePath determines path to resources including <thisDir> prefix for embedded resources.
func getResourcesWritePath(cfg *viper.Viper, pathFlag string, embeddedFlag string) string {
	pathValue := cfg.GetString(pathFlag)
	if pathValue == "" {
		pathValue = path.Join(thisDir, embeddedFlag, cfg.GetString(embeddedFlag))
		return pathValue
	}
	if path.IsAbs(pathValue) {
		return pathValue
	}
	return path.Join(thisDir, "..", pathValue)
}

func getFileReader(cfg *viper.Viper, pathFlag string, embeddedFlag string) (resourceReader, string) {
	pathValue := cfg.GetString(pathFlag)
	if pathValue == "" {
		pathValue = path.Join(embeddedFlag, cfg.GetString(embeddedFlag))
		return embeddedFS, pathValue
	}
	return ReaderReader{}, pathValue
}

func getSPDXReader(cfg *viper.Viper) (resourceReader, string) {
	return getFileReader(cfg, configurer.SpdxPathFlag, configurer.SpdxFlag)
}

func getCustomReader(cfg *viper.Viper) (resourceReader, string) {
	return getFileReader(cfg, configurer.CustomPathFlag, configurer.CustomFlag)
}

func ReadSPDXJSONFiles(cfg *viper.Viper) (licenseListBytes []byte, exceptionsBytes []byte, err error) {
	rr, spdxPath := getSPDXReader(cfg)
	jsonSubDir := "json"
	licensesJSON := path.Join(spdxPath, jsonSubDir, "licenses.json")
	exceptionsJSON := path.Join(spdxPath, jsonSubDir, "exceptions.json")
	licenseListBytes, err = rr.ReadFile(licensesJSON)
	if err != nil {
		return
	}
	exceptionsBytes, err = rr.ReadFile(exceptionsJSON)
	return
}

func getSPDXTemplateFilePath(id string, isDeprecated bool, templatePath string) string {
	f := id + ".template.txt"
	if isDeprecated {
		f = "deprecated_" + f
	}
	f = path.Join(templatePath, f)
	return f
}

func getSPDXPreCheckFilePath(id string, isDeprecated bool, preCheckPath string) string {
	f := id + ".json"
	if isDeprecated {
		f = "deprecated_" + f
	}
	f = path.Join(preCheckPath, f)
	return f
}

func ReadSPDXTemplateFile(cfg *viper.Viper, id string, isDeprecated bool) ([]byte, string, error) {
	rr, spdxPath := getSPDXReader(cfg)
	templatePath := path.Join(spdxPath, "template")
	f := getSPDXTemplateFilePath(id, isDeprecated, templatePath)
	tBytes, err := rr.ReadFile(f)
	return tBytes, f, err
}

func ReadSPDXPreCheckFile(cfg *viper.Viper, id string, isDeprecated bool) ([]byte, error) {
	rr, spdxPath := getSPDXReader(cfg)
	preCheckPath := path.Join(spdxPath, "precheck")
	f := getSPDXPreCheckFilePath(id, isDeprecated, preCheckPath)
	tBytes, err := rr.ReadFile(f)
	return tBytes, err
}

func (r *Resources) ReadCustomLicensePatternIds() (ids []string, err error) {
	rr, customPath := getCustomReader(r.config)
	patternPath := path.Join(customPath, "license_patterns")
	des, err := rr.ReadDir(patternPath)
	if err != nil {
		return
	}
	for _, de := range des {
		ids = append(ids, de.Name())
	}
	return
}

func (r *Resources) ReadCustomLicensePatternsDir(id string) ([]fs.DirEntry, string, error) {
	rr, customPath := getCustomReader(r.config)
	idPath := path.Join(customPath, "license_patterns", id)
	des, err := rr.ReadDir(idPath)
	return des, idPath, err
}

func (r *Resources) ReadCustomDir(dir string) ([]fs.DirEntry, string, error) {
	rr, customPath := getCustomReader(r.config)
	dirPath := path.Join(customPath, dir)
	des, err := rr.ReadDir(dirPath)
	return des, dirPath, err
}

func (r *Resources) ReadCustomFile(filePath string) ([]byte, error) {
	rr, _ := getCustomReader(r.config)
	b, err := rr.ReadFile(filePath)
	return b, err
}

func mkdirAll(cfg *viper.Viper, pathFlag string, embeddedFlag string, dirs ...string) error {
	destPath := getResourcesWritePath(cfg, pathFlag, embeddedFlag)
	for _, dir := range dirs {
		destSubDir := path.Join(destPath, dir)
		if err := os.MkdirAll(destSubDir, os.ModePerm); err != nil {
			return fmt.Errorf("cannot create destination dir %v error: %w", destSubDir, err)
		}
		des, err := os.ReadDir(destSubDir)
		if err != nil {
			return fmt.Errorf("cannot read destination dir %v error: %w", destSubDir, err)
		}
		if len(des) > 0 {
			return fmt.Errorf("destination dir %v is not empty", destSubDir)
		}
	}
	return nil
}

func MkdirAllSPDX(cfg *viper.Viper) error {
	dirs := []string{"template", "precheck", "json", "testdata", "testdata/invalid"}
	return mkdirAll(cfg, configurer.SpdxPathFlag, configurer.SpdxFlag, dirs...)
}

func MkdirAllCustom(cfg *viper.Viper, id string) error {
	dirs := []string{"license_patterns/" + id}
	return mkdirAll(cfg, configurer.CustomPathFlag, configurer.CustomFlag, dirs...)
}

func GetSPDXPath(cfg *viper.Viper, dir string) string {
	return path.Join(getResourcesPath(cfg, configurer.SpdxPathFlag, configurer.SpdxFlag), dir)
}

func GetCustomPath(cfg *viper.Viper, dir string) string {
	return path.Join(getResourcesPath(cfg, configurer.CustomPathFlag, configurer.CustomFlag), dir)
}

func WriteSPDXFile(cfg *viper.Viper, bytes []byte, ff ...string) error {
	f := path.Join(getResourcesWritePath(cfg, configurer.SpdxPathFlag, configurer.SpdxFlag), path.Join(ff...))
	return os.WriteFile(f, bytes, 0o600)
}

func WriteCustomFile(cfg *viper.Viper, bytes []byte, ff ...string) error {
	f := path.Join(getResourcesWritePath(cfg, configurer.CustomPathFlag, configurer.CustomFlag), path.Join(ff...))
	return os.WriteFile(f, bytes, 0o600)
}
