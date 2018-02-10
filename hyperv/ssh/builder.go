package ssh

import (
	"github.com/hashicorp/packer/packer"
)

type Builder struct { }

func (b *Builder) Prepare(raws ...interface{}) ([]string, error) {
	return nil, nil
}

func (b *Builder) Run(ui packer.Ui, hook packer.Hook, cache packer.Cache) (packer.Artifact, error) {
	return nil, nil
}

func (b *Builder) Cancel() {

}
