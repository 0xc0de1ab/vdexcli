package modifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xc0de1ab/vdexcli/internal/model"
)

// mockBuilder verifies VerifierBuilder can be mocked.
type mockBuilder struct {
	called string
}

func (m *mockBuilder) BuildReplacement(_ []model.DexReport, _ []uint32, _ model.VerifierPatchSpec) ([]byte, []string, error) {
	m.called = "replace"
	return []byte{1, 2, 3}, nil, nil
}

func (m *mockBuilder) BuildMerge(_ []model.DexReport, _ []uint32, _ model.VdexSection, _ []byte, _ model.VerifierPatchSpec) ([]byte, []string, error) {
	m.called = "merge"
	return []byte{4, 5, 6}, nil, nil
}

func TestVerifierBuilder_Mock(t *testing.T) {
	var b VerifierBuilder = &mockBuilder{}
	payload, _, err := b.BuildReplacement(nil, nil, model.VerifierPatchSpec{})
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, payload)
	assert.Equal(t, "replace", b.(*mockBuilder).called)
}

func TestVerifierBuilder_Default(t *testing.T) {
	var b VerifierBuilder = DefaultBuilder{}
	_, _, err := b.BuildReplacement(nil, nil, model.VerifierPatchSpec{})
	assert.Error(t, err, "no dex count → error expected")
}

func TestVerifierComparator_Default(t *testing.T) {
	var c VerifierComparator = DefaultComparator{}
	_, _, _, err := c.Compare(nil, model.VdexSection{}, nil, nil, nil)
	assert.Error(t, err)
}

func TestPatchLoader_Default(t *testing.T) {
	var l PatchLoader = DefaultPatchLoader{}
	_, _, err := l.Load("/nonexistent")
	assert.Error(t, err)
}

func TestOutputWriter_Default(t *testing.T) {
	var w OutputWriter = DefaultOutputWriter{}
	err := w.WriteAtomic("/nonexistent/dir/file", []byte("data"))
	assert.Error(t, err)
}
