package optimization

import (
	"reflect"
	"testing"
)

func TestAbstraction(t *testing.T) {
	type args struct {
		s       string
		pibrahimsqload string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "inHTML-none",
			args: args{
				s:       "asdf<br><aether>1234",
				pibrahimsqload: "<aether>",
			},
			want: []string{"inHTML-none"},
		},
		{
			name: "inJS-none",
			args: args{
				s:       "<script><aether></script>",
				pibrahimsqload: "<aether>",
			},
			want: []string{"inJS-none"},
		},

		{
			name: "inJS-double",
			args: args{
				s:       "<script>var a= \"<aether>\"</script>",
				pibrahimsqload: "<aether>",
			},
			want: []string{"inJS-double"},
		},
		{
			name: "inJS-single",
			args: args{
				s:       "<script>var a = '<aether>'</script>",
				pibrahimsqload: "<aether>",
			},
			want: []string{"inJS-single"},
		},

		{
			name: "inJS-backtick",
			args: args{
				s:       "<script>`<aether>`</script>",
				pibrahimsqload: "<aether>",
			},
			want: []string{"inJS-backtick"},
		},
		{
			name: "inATTR-none",
			args: args{
				s:       "<a href=aether>zzz</a>",
				pibrahimsqload: "aether",
			},
			want: []string{"inATTR-none"},
		},
		{
			name: "inATTR-double",
			args: args{
				s:       "<a href=\"aether\">zzz</a>",
				pibrahimsqload: "aether",
			},
			want: []string{"inATTR-double"},
		},
		{
			name: "inATTR-single",
			args: args{
				s:       "<a href='aether'>zzz</a>",
				pibrahimsqload: "aether",
			},
			want: []string{"inATTR-single"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Abstraction(tt.args.s, tt.args.pibrahimsqload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Abstraction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setPointer(t *testing.T) {
	type args struct {
		arr     []int
		pointer map[int]string
		key     string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test",
			args: args{
				arr:     []int{1, 2, 3},
				pointer: map[int]string{1: "1"},
				key:     "1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setPointer(tt.args.arr, tt.args.pointer, tt.args.key)
		})
	}
}

func TestFindIndexesInLine(t *testing.T) {
	type args struct {
		text     string
		key      string
		lineSize int
		pointing int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "test",
			args: args{
				text:     "abcd",
				key:      "b",
				lineSize: 1,
				pointing: 1,
			},
			want: []int{3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindIndexesInLine(tt.args.text, tt.args.key, tt.args.lineSize, tt.args.pointing); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindIndexesInLine() = %v, want %v", got, tt.want)
			}
		})
	}
}
