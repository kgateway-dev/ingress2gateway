package glooedge

import (
	"context"
	"fmt"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const Name = "gloo-edge"

func init() {
	i2gw.ProviderConstructorByName[Name] = NewProvider
}

type Provider struct {
	storage                *storage
	resourceReader         *resourceReader
	resourcesToIRConverter *resourcesToIRConverter
}

func NewProvider(conf *i2gw.ProviderConf) i2gw.Provider {
	return &Provider{
		storage:                newResourcesStorage(),
		resourceReader:         newResourceReader(conf),
		resourcesToIRConverter: newResourcesToIRConverter(),
	}
}

func (p *Provider) ToIR() (emitterir.EmitterIR, field.ErrorList) {
	pIR, errs := p.resourcesToIRConverter.convert(p.storage)
	return providerir.ToEmitterIR(pIR), errs
}

func (p *Provider) ReadResourcesFromCluster(ctx context.Context) error {
	storage, err := p.resourceReader.readResourcesFromCluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to read gloo edge resources from cluster: %w", err)
	}
	p.storage = storage
	return nil
}

func (p *Provider) ReadResourcesFromFile(_ context.Context, filename string) error {
	storage, err := p.resourceReader.readResourcesFromFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read gloo edge resources from file: %w", err)
	}
	p.storage = storage
	return nil
}