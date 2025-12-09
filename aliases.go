package aidr

import (
	"github.com/crowdstrike/aidr-go/internal/apierror"
	"github.com/crowdstrike/aidr-go/packages/param"
)

// aliased to make [param.APIUnion] private when embedding
type paramUnion = param.APIUnion

// aliased to make [param.APIObject] private when embedding
type paramObj = param.APIObject

type Error = apierror.Error
