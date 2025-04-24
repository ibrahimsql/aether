package optimization

import (
	"testing"
)

// import "github.com/ibrahimsql/aether/v2/pkg/model"
// TODO: Update or provide the correct model import after refactoring.

func Test_CheckInspectionParam(t *testing.T) {
	type args struct {
		options model.Options
		k       string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test - true",
			args: args{
				options: model.Options{
					UniqParam: []string{
						"1234",
						"cat",
					},
				},
				k: "1234",
			},
			want: true,
		},
		{
			name: "test - true",
			args: args{
				options: model.Options{
					UniqParam: []string{
						"cat",
						"1234",
					},
				},
				k: "1234",
			},
			want: true,
		},

		{
			name: "test - true",
			args: args{
				options: model.Options{
					UniqParam: []string{},
				},
				k: "5555",
			},
			want: true,
		},
		{
			name: "test - false",
			args: args{
				options: model.Options{
					UniqParam: []string{
						"1234",
						"cat",
					},
				},
				k: "5555",
			},
			want: false,
		},
		{
			name: "test - false",
			args: args{
				options: model.Options{
					IgnoreParams: []string{
						"1234",
						"cat",
					},
				},
				k: "1234",
			},
			want: false,
		},
		{
			name: "test - false",
			args: args{
				options: model.Options{
					IgnoreParams: []string{
						"1234",
						"cat",
					},
				},
				k: "5555",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckInspectionParam(tt.args.options, tt.args.k); got != tt.want {
				t.Errorf("CheckInspectionParam() = %v, want %v", got, tt.want)
			}
		})
	}
}
