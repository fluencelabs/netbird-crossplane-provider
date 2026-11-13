/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nbpolicy

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/go-logr/logr"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

func TestObserve(t *testing.T) {
	type fields struct {
		authManager *auth.AuthManager
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalObservation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		// TODO: Add test cases.
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{authManager: tc.fields.authManager}
			got, err := e.Observe(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}

func strp(s string) *string { return &s }

func gm(id, name string) v1alpha1.GroupMinimum {
	g := v1alpha1.GroupMinimum{}
	if id != "" {
		g.Id = strp(id)
	}
	if name != "" {
		g.Name = strp(name)
	}
	return g
}

var testGroups = []nbapi.Group{
	{Id: "g-ops", Name: "ops"},
	{Id: "g-dev", Name: "dev"},
	{Id: "g-dup1", Name: "dup"},
	{Id: "g-dup2", Name: "dup"},
}

func TestNbToApiGroupMinimums(t *testing.T) {
	cases := map[string]struct {
		in      *[]v1alpha1.GroupMinimum
		want    *[]string
		wantErr string
	}{
		"Nil": {in: nil, want: nil},
		"ByID": {
			in:   &[]v1alpha1.GroupMinimum{gm("g-ops", "")},
			want: &[]string{"g-ops"},
		},
		"ByName": {
			in:   &[]v1alpha1.GroupMinimum{gm("", "dev")},
			want: &[]string{"g-dev"},
		},
		"Mixed": {
			in:   &[]v1alpha1.GroupMinimum{gm("", "dev"), gm("g-ops", ""), gm("g-dup1", "dup")},
			want: &[]string{"g-dev", "g-ops", "g-dup1"},
		},
		"IDWinsOverName": {
			in:   &[]v1alpha1.GroupMinimum{gm("g-ops", "dev")},
			want: &[]string{"g-ops"},
		},
		"StaleIDFallsBackToName": {
			in:   &[]v1alpha1.GroupMinimum{gm("g-gone", "dev")},
			want: &[]string{"g-dev"},
		},
		"UnknownName": {
			in:      &[]v1alpha1.GroupMinimum{gm("", "dev"), gm("", "nope")},
			wantErr: `group not found by name: "nope"`,
		},
		"UnknownID": {
			in:      &[]v1alpha1.GroupMinimum{gm("g-gone", "")},
			wantErr: `group not found by id: "g-gone"`,
		},
		"DuplicateName": {
			in:      &[]v1alpha1.GroupMinimum{gm("", "dup")},
			wantErr: `group name "dup" is ambiguous: 2 groups carry it (ids g-dup1, g-dup2); reference it by id`,
		},
		"Empty": {
			in:      &[]v1alpha1.GroupMinimum{{}},
			wantErr: "group reference missing both id and name",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := NbToApiGroupMinimums(tc.in, testGroups)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tc.wantErr {
				t.Fatalf("error: want %q, got %q", tc.wantErr, gotErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("NbToApiGroupMinimums(...): -want, +got:\n%s", diff)
			}
		})
	}
}

func apiRule(sources, destinations []nbapi.GroupMinimum) nbapi.Policy {
	return nbapi.Policy{Rules: []nbapi.PolicyRule{{
		Action:        "accept",
		Bidirectional: true,
		Protocol:      "all",
		Sources:       &sources,
		Destinations:  &destinations,
	}}}
}

func specRule(sources, destinations []v1alpha1.GroupMinimum) v1alpha1.NbPolicyParameters {
	return v1alpha1.NbPolicyParameters{Rules: []v1alpha1.PolicyRule{{
		Action:        "accept",
		Bidirectional: true,
		Protocol:      "all",
		Sources:       &sources,
		Destinations:  &destinations,
	}}}
}

func TestIsApiToNBPolicyUpToDateGroups(t *testing.T) {
	api := apiRule(
		[]nbapi.GroupMinimum{{Id: "g-ops", Name: "ops"}},
		[]nbapi.GroupMinimum{{Id: "g-dev", Name: "dev"}, {Id: "g-dup2", Name: "dup"}},
	)
	cases := map[string]struct {
		spec v1alpha1.NbPolicyParameters
		want bool
	}{
		"ByIDMatches": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("g-ops", "")}, []v1alpha1.GroupMinimum{gm("g-dev", ""), gm("g-dup2", "")}),
			want: true,
		},
		"NameOnlyMatches": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "ops")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("g-dup2", "")}),
			want: true,
		},
		"NameOnlyDiffers": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "dev")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("g-dup2", "")}),
			want: false,
		},
		"OrderDiffers": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "ops")}, []v1alpha1.GroupMinimum{gm("g-dup2", ""), gm("", "dev")}),
			want: false,
		},
		"UnresolvableName": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "nope")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("g-dup2", "")}),
			want: false,
		},
		"AmbiguousName": {
			spec: specRule([]v1alpha1.GroupMinimum{gm("", "ops")}, []v1alpha1.GroupMinimum{gm("", "dev"), gm("", "dup")}),
			want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{log: logr.Discard()}
			if got := IsApiToNBPolicyUpToDate(tc.spec, &api, testGroups, e); got != tc.want {
				t.Errorf("IsApiToNBPolicyUpToDate(...) = %v, want %v", got, tc.want)
			}
		})
	}
}
