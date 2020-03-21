package ekms

import (
	"context"
	"reflect"
	"testing"
)

func Test_newEKMSAEAD(t *testing.T) {
	type args struct {
		ctx     context.Context
		keyURI  string
		autogen bool
	}
	tests := []struct {
		name    string
		args    args
		wantP   *ekmsAEAD
		wantErr bool
	}{
		{
			name:    "Default",
			args:    args{
				ctx:     context.TODO(),
				keyURI:  "https://",
				autogen: false,
			},
			wantP:   nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotP, err := newEKMSAEAD(tt.args.ctx, tt.args.keyURI, tt.args.autogen)
			if (err != nil) != tt.wantErr {
				t.Errorf("newEKMSAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotP, tt.wantP) {
				t.Errorf("newEKMSAEAD() gotP = %v, want %v", gotP, tt.wantP)
			}
		})
	}
}