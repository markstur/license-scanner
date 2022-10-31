// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/IBM/license-scanner/configurer"
	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
	"github.com/IBM/license-scanner/resources"

	"github.com/mrutkows/sbom-utility/log"

	"github.com/spf13/viper"
)

var (
	Logger            = log.NewLogger(log.INFO)
	_, thisFile, _, _ = runtime.Caller(0) // Dirs/files are relative to this file
	thisDir           = filepath.Dir(thisFile)
)

func Import(cfg *viper.Viper) error {
	if cfg.GetString(configurer.AddAllFlag) == "" {
		return nil // nothing to import
	}
	doImportSPDX := cfg.GetString(configurer.SpdxPathFlag) != "" || cfg.GetString(configurer.SpdxFlag) != configurer.DefaultResource
	doImportCustom := cfg.GetString(configurer.CustomPathFlag) != "" || cfg.GetString(configurer.CustomFlag) != configurer.DefaultResource

	if !doImportCustom && !doImportSPDX {
		return fmt.Errorf("importing templates requires a non-default destination")
	} else if doImportCustom && doImportSPDX {
		return fmt.Errorf("importing templates requires one non-default SPDX or custom destination -- found both")
	}

	if doImportSPDX {
		if err := importSPDX(cfg); err != nil {
			return err
		}
	}

	if doImportCustom {
		if err := importCustom(cfg); err != nil {
			return err
		}
	}
	return nil
}

func importSPDX(cfg *viper.Viper) error {
	// input dir is relative to root (if not an absolute path)
	addAllDir := cfg.GetString("addAll")

	if !path.IsAbs(addAllDir) {
		addAllDir = path.Join(thisDir, "..", addAllDir)
	}

	// sources
	licensesJSON := path.Join(addAllDir, "json", "licenses.json")
	exceptionsJSON := path.Join(addAllDir, "json", "exceptions.json")
	templateSrcDir := path.Join(addAllDir, "template")
	textSrcDir := path.Join(addAllDir, "text")

	SPDXLicenseListBytes, err := os.ReadFile(licensesJSON)
	if err != nil {
		return fmt.Errorf("read SPDXLicenseListJSON from %v error: %w", licensesJSON, err)
	}
	licenseList, err := licenses.ReadSPDXLicenseListJSON(SPDXLicenseListBytes)
	if err != nil {
		return fmt.Errorf("unmarshal SPDXLicenseListJSON from %v error: %w", licensesJSON, err)
	}
	licenseListVersion := licenseList.LicenseListVersion

	SPDXExceptionsListBytes, err := os.ReadFile(exceptionsJSON)
	if err != nil {
		return fmt.Errorf("read exceptions JSON from %v error: %w", exceptionsJSON, err)
	}
	exceptionsList, err := licenses.ReadSPDXLicenseListJSON(SPDXExceptionsListBytes)
	if err != nil {
		return fmt.Errorf("unmarshal SPDXLicenseListJSON from %v error: %w", exceptionsJSON, err)
	}
	exceptionsListVersion := exceptionsList.LicenseListVersion

	if licenseListVersion != exceptionsListVersion {
		return fmt.Errorf("license list version '%v' does not match exception list version '%v'", licenseListVersion, exceptionsListVersion)
	}

	templateDEs, err := os.ReadDir(templateSrcDir)
	if err != nil {
		return err
	}
	if len(templateDEs) < 1 {
		return fmt.Errorf("template source dir %v is empty", templateSrcDir)
	}

	if err := resources.MkdirAllSPDX(cfg); err != nil {
		return err
	}

	if err := resources.WriteSPDXFile(cfg, SPDXLicenseListBytes, "json", "licenses.json"); err != nil {
		return err
	}
	if err := resources.WriteSPDXFile(cfg, SPDXExceptionsListBytes, "json", "exceptions.json"); err != nil {
		return err
	}

	errorCount := 0
	for _, de := range templateDEs {
		templateName := de.Name()
		id := strings.TrimSuffix(templateName, ".template.txt")
		templateFile := path.Join(templateSrcDir, templateName)
		precheckName := id + ".json"
		textName := id + ".txt"
		textFile := path.Join(textSrcDir, textName)
		templateBytes, err := os.ReadFile(templateFile)
		if err != nil {
			return err
		}
		textBytes, err := os.ReadFile(textFile)
		if err != nil {
			return err
		}

		staticBlocks, err := validate(id, templateBytes, textBytes, templateFile)
		if err != nil {
			deprecatedPrefix := "deprecated_"
			if strings.HasPrefix(id, deprecatedPrefix) {
				Logger.Infof("template ID %v is not valid retrying w/o testdata prefix", id)
				altTextFile := path.Join(textSrcDir, strings.TrimPrefix(id+".txt", deprecatedPrefix))
				textBytes, err = os.ReadFile(altTextFile)
				if err != nil {
					return err
				}
				staticBlocks, err = validate(id, templateBytes, textBytes, templateFile)
			}
			if err != nil {
				_ = Logger.Errorf("template ID %v is not valid", id)
				errorCount++
				writeInvalidSPDXFiles(cfg, templateName, templateBytes, textName, textBytes)
			} else if err := writeSPDXFiles(cfg, templateName, templateBytes, textName, textBytes, precheckName, staticBlocks); err != nil {
				return err
			}
		} else if err := writeSPDXFiles(cfg, templateName, templateBytes, textName, textBytes, precheckName, staticBlocks); err != nil {
			return err
		}
	}
	if errorCount > 0 {
		return fmt.Errorf("%v templates could not be validated", errorCount)
	}
	return nil
}

func writeSPDXFiles(cfg *viper.Viper, templateName string, templateBytes []byte, textName string, textBytes []byte, precheckName string, staticBlocks []string) error {

	if err := resources.WriteSPDXFile(cfg, templateBytes, "template", templateName); err != nil {
		return Logger.Errorf("error writing template for %v: %w", templateName, err)
	}
	if err := resources.WriteSPDXFile(cfg, textBytes, "testdata", textName); err != nil {
		return Logger.Errorf("error writing testdata for %v: %w", textName, err)
	}
	precheckBytes, err := getPreChecksBytes(staticBlocks)
	if err != nil {
		return Logger.Errorf("error getting precheck bytes for %v: %w", templateName, err)
	}
	if err := resources.WriteSPDXFile(cfg, precheckBytes, "precheck", precheckName); err != nil {
		return Logger.Errorf("error writing precheck file for %v: %w", templateName, err)
	}

	return nil
}

// writeInvalidSPDXFiles stashes the template and text under testdata/invalid for further (manual) examination
func writeInvalidSPDXFiles(cfg *viper.Viper, templateName string, templateBytes []byte, textName string, textBytes []byte) {
	if err := resources.WriteSPDXFile(cfg, templateBytes, "testdata", "invalid", templateName); err != nil {
		_ = Logger.Errorf("error writing template for %v: %w", templateName, err)
	}
	if err := resources.WriteSPDXFile(cfg, textBytes, "testdata", "invalid", textName); err != nil {
		_ = Logger.Errorf("error writing testdata for %v: %w", textName, err)
	}
}

func importCustom(cfg *viper.Viper) error {
	// input dir is relative to root (if not an absolute path)
	addAllDir := cfg.GetString("addAll")

	if !path.IsAbs(addAllDir) {
		addAllDir = path.Join(thisDir, "..", addAllDir)
	}

	// Create and input resource reader using the input dir as custom path
	inputConfig, err := configurer.InitConfig(nil)
	if err != nil {
		return err
	}
	inputConfig.Set(configurer.CustomPathFlag, addAllDir)
	inputResources := resources.NewResources(inputConfig)
	licenseIds, err := inputResources.ReadCustomLicensePatternIds()

	for _, id := range licenseIds {
		des, idPath, err := inputResources.ReadCustomLicensePatternsDir(id)
		if err != nil {
			return err
		}

		if err := resources.MkdirAllCustom(cfg, id); err != nil {
			return err
		}

		for _, de := range des {
			if de.IsDir() {
				continue
			}
			fileName := de.Name()
			base := path.Base(fileName)
			filePath := path.Join(idPath, fileName)
			lowerFileName := strings.ToLower(fileName)
			switch {
			// the JSON payload is always stored in license_info.txt
			case lowerFileName == licenses.LicenseInfoJSON:
				bytes, err := os.ReadFile(filePath)
				if err != nil {
					return err
				}
				// Verify that unmarshal doesn't fail
				if _, err := licenses.ReadLicenseInfoJSON(bytes); err != nil {
					return Logger.Errorf("Unmarshal LicenseInfo from %v using LicenseReader error: %v", filePath, err)
				}
				if err := resources.WriteCustomFile(cfg, bytes, "license_patterns", id, fileName); err != nil {
					return err
				}
			// all other files starting with "license_" are primary license patterns. Validate and copy primary and associated patterns.
			case strings.HasPrefix(lowerFileName, licenses.PrimaryPattern), strings.HasPrefix(lowerFileName, licenses.AssociatedPattern), strings.HasPrefix(lowerFileName, licenses.OptionalPattern):
				bytes, err := os.ReadFile(filePath)
				if err != nil {
					return err
				}
				// Verify that we can normalize the input text and create a regex
				normalizedData := normalizer.NewNormalizationData(string(bytes), true)
				err = normalizedData.NormalizeText()
				if err == nil {
					_, err = licenses.GenerateRegexFromNormalizedText(normalizedData.NormalizedText)
					if err != nil {
						return fmt.Errorf("cannot generate re: %v", err)
					}
				}

				if err := resources.WriteCustomFile(cfg, bytes, "license_patterns", id, fileName); err != nil {
					return err
				}

				staticBlocks := GetStaticBlocks(normalizedData)
				precheckBytes, err := getPreChecksBytes(staticBlocks)
				if err != nil {
					return Logger.Errorf("error getting precheck bytes for %v: %w", base, err)
				}
				f := "prechecks_" + base // Add prefix
				ext := path.Ext(f)
				f = f[0:len(f)-len(ext)] + ".json" // Replace .txt with .json
				if err := resources.WriteCustomFile(cfg, precheckBytes, "license_patterns", id, f); err != nil {
					return Logger.Errorf("error writing precheck file for %v: %w", fileName, err)
				}
			}
		}
	}
	return nil
}
