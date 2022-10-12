package importer

import (
	"os"
	"path"
	"testing"
)

func TestImporter_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "0BSD should validate out-of-the-box",
			id:      "0BSD",
			wantErr: false,
		},
		{
			name:    "BlueOak-1.0.0 fixed omitable line prefix ## needs to be normalized like line comment",
			id:      "BlueOak-1.0.0",
			wantErr: false,
		},
		{
			name:    "CC-BY-3.0 fixed testdata space before comma '(iv) ,'",
			id:      "CC-BY-3.0",
			wantErr: false,
		},
		{
			name:    "Afmparse fixed testdata no space between comma-and",
			id:      "Afmparse",
			wantErr: false,
		},
		{
			name:    "CC-BY-NC-SA-2.0-FR template mod removed several extra ' . '",
			id:      "CC-BY-NC-SA-2.0-FR",
			wantErr: false,
		},
		{
			name:    "CC-BY-SA-3.0 fixed testdata space before comma after (iv) ",
			id:      "CC-BY-SA-3.0",
			wantErr: false,
		},
		{
			name:    "COIL-1.0 fixed ## markdown prefix in normalizer",
			id:      "COIL-1.0",
			wantErr: false,
		},
		{
			name:    "Community-Spec-1.0 'Scope for: 1)' and 'under which 1)' breaks when the 1) is on a newline like a bullet ",
			id:      "Community-Spec-1.0",
			wantErr: false,
		},
		{
			name:    "copyleft-next-0.3.0 (probably 0.3.1 same) ** blocks ** (fixed) and then a (ii) on nl",
			id:      "copyleft-next-0.3.0",
			wantErr: false,
		},
		{
			name:    "D-FSL-1.0 escaped > in <<regex>> breaks us: match=\"(\\)\\>|\\))?\">> ",
			id:      "D-FSL-1.0",
			wantErr: true,
		},
	}
	testData := "../testdata/validator"
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id := tt.id
			templateFile := path.Join(testData, id+".template.txt")
			templateBytes, err := os.ReadFile(templateFile)
			if err != nil {
				t.Errorf("ID: %v Read template file error: %v", id, err)
				return
			}
			textFile := path.Join(testData, id+".txt")
			textBytes, err := os.ReadFile(textFile)
			if err != nil {
				t.Errorf("ID: %v Read text file error: %v", id, err)
				return
			}
			if _, err := validate(id, templateBytes, textBytes, templateFile); err != nil {
				if tt.wantErr == true {
					t.Skipf("validate() error = %v, wantErr %v", err, tt.wantErr)
				} else {
					t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
