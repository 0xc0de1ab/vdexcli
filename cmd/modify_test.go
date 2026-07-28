package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

func TestValidateModifyVersion(t *testing.T) {
	require.NoError(t, validateModifyVersion(&model.VdexReport{
		Header: model.VdexHeader{Version: model.VdexCurrentVersion},
	}))

	err := validateModifyVersion(&model.VdexReport{
		Header: model.VdexHeader{Version: "026"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only VDEX v027")
	assert.Contains(t, err.Error(), "incompatible verifier encoding")
}
