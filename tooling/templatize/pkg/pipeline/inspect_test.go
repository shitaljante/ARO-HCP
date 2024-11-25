package pipeline

import (
	"bytes"
	"context"
	"io"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/Azure/ARO-HCP/tooling/templatize/pkg/config"
)

func TestInspectVars(t *testing.T) {
	testCases := []struct {
		name     string
		caseStep *step
		options  *InspectOptions
		expected string
		err      string
	}{
		{
			name: "basic",
			caseStep: &step{
				Action: "Shell",
				Env: []EnvVar{
					{
						Name:      "FOO",
						ConfigRef: "foo",
					},
				},
			},
			options: &InspectOptions{
				Vars: config.Variables{
					"foo": "bar",
				},
				Format: "shell",
			},
			expected: "export FOO=\"bar\"\n",
		},
		{
			name: "makefile",
			caseStep: &step{
				Action: "Shell",
				Env: []EnvVar{
					{
						Name:      "FOO",
						ConfigRef: "foo",
					},
				},
			},
			options: &InspectOptions{
				Vars: config.Variables{
					"foo": "bar",
				},
				Format: "makefile",
			},
			expected: "FOO ?= bar\n",
		},
		{
			name:     "failed action",
			caseStep: &step{Action: "Unknown"},
			err:      "inspecting step variables not implemented for action type Unknown",
		},
		{
			name:     "failed format",
			caseStep: &step{Action: "Shell"},
			options:  &InspectOptions{Format: "unknown"},
			err:      "unknown output format \"unknown\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := inspectVars(tc.caseStep, tc.options, buf)
			if tc.err == "" {
				assert.NilError(t, err)
				assert.Equal(t, buf.String(), tc.expected)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestInspect(t *testing.T) {
	p := Pipeline{
		ResourceGroups: []*resourceGroup{{
			Steps: []*step{
				{
					Name: "step1",
				},
			},
		},
		},
	}
	opts := NewInspectOptions(config.Variables{}, "", "step1", "scope", "format")

	opts.ScopeFunctions = map[string]StepInspectScope{
		"scope": func(s *step, o *InspectOptions, w io.Writer) error {
			assert.Equal(t, s.Name, "step1")
			return nil
		},
	}

	err := p.Inspect(context.Background(), opts, nil)
	assert.NilError(t, err)
}

func TestInspectWrongScope(t *testing.T) {
	p := Pipeline{
		ResourceGroups: []*resourceGroup{{
			Steps: []*step{
				{
					Name: "step1",
				},
			},
		},
		},
	}
	opts := NewInspectOptions(config.Variables{}, "", "step1", "foo", "format")

	err := p.Inspect(context.Background(), opts, nil)
	assert.Error(t, err, "unknown inspect scope \"foo\"")
}
