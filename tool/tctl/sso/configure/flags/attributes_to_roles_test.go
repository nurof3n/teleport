package flags

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func Test_attributesToRolesParser_Set(t *testing.T) {
	tests := []struct {
		name       string
		parser     attributesToRolesParser
		arg        string
		wantErr    bool
		wantParser attributesToRolesParser
	}{
		{
			name:   "one set of correct args",
			parser: attributesToRolesParser{mappings: &[]types.AttributeMapping{}},
			arg:    "foo,bar,baz",
			wantParser: attributesToRolesParser{mappings: &[]types.AttributeMapping{
				{
					Name:  "foo",
					Value: "bar",
					Roles: []string{"baz"},
				}}},
			wantErr: false,
		},
		{
			name: "two sets of correct args",
			parser: attributesToRolesParser{mappings: &[]types.AttributeMapping{
				{
					Name:  "foo",
					Value: "bar",
					Roles: []string{"baz"},
				}}},
			arg: "aaa,bbb,ccc,ddd",
			wantParser: attributesToRolesParser{mappings: &[]types.AttributeMapping{
				{
					Name:  "foo",
					Value: "bar",
					Roles: []string{"baz"},
				},
				{
					Name:  "aaa",
					Value: "bbb",
					Roles: []string{"ccc", "ddd"},
				}}},
			wantErr: false,
		},
		{
			name:       "one set of incorrect args",
			parser:     attributesToRolesParser{mappings: &[]types.AttributeMapping{}},
			arg:        "abracadabra",
			wantParser: attributesToRolesParser{mappings: &[]types.AttributeMapping{}},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parser.Set(tt.arg)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantParser, tt.parser)
			}
		})
	}
}
