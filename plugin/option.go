package plugin

import (
	"fmt"

	"github.com/Azure/go-autorest/autorest"
	"google.golang.org/protobuf/types/known/structpb"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(&opts); err != nil {
			return options{}, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// options = how options are represented
type options struct {
	withHostCatalogAttrs  *structpb.Struct
	withPersistedData     *structpb.Struct
	withSubscriptionId    string
	withAuthorizer        autorest.Authorizer
	withUserAgent         string
	withBaseUrl           string
	withAuthorizationInfo *AuthorizationInfo
	withClientId          string
	withSecretId          string
}

func getDefaultOptions() options {
	return options{
		withUserAgent: "hashicorp-boundary",
	}
}

// WithHostCatalogAttrs contains attributes to insert in a host catalog message
func WithHostCatalogAttrs(with map[string]interface{}) Option {
	return func(o *options) error {
		s, err := structpb.NewStruct(with)
		if err != nil {
			return fmt.Errorf("error creating proto struct from map: %w", err)
		}
		o.withHostCatalogAttrs = s
		return nil
	}
}

// WithPersistedData contains attributes to insert in a persisted data message
func WithPersistedData(with map[string]interface{}) Option {
	return func(o *options) error {
		s, err := structpb.NewStruct(with)
		if err != nil {
			return fmt.Errorf("error creating proto struct from map: %w", err)
		}
		o.withPersistedData = s
		return nil
	}
}

// WithSubscriptionId contains the subscription ID to use
func WithSubscriptionId(with string) Option {
	return func(o *options) error {
		o.withSubscriptionId = with
		return nil
	}
}

// WithAuthorizer contains the authorizer to user
func WithAuthorizer(with autorest.Authorizer) Option {
	return func(o *options) error {
		o.withAuthorizer = with
		return nil
	}
}

// WithUserAgent contains the user agent to use
func WithUserAgent(with string) Option {
	return func(o *options) error {
		o.withUserAgent = with
		return nil
	}
}

// WithBaseUrl contains the base URL to use
func WithBaseUrl(with string) Option {
	return func(o *options) error {
		o.withBaseUrl = with
		return nil
	}
}

// WithAuthorizationInfo contains the authorization information to use
func WithAuthorizationInfo(with *AuthorizationInfo) Option {
	return func(o *options) error {
		o.withAuthorizationInfo = with
		return nil
	}
}

// WithClientId contains the client ID to use
func WithClientId(with string) Option {
	return func(o *options) error {
		o.withClientId = with
		return nil
	}
}

// WithSecretId contains the secret ID to use
func WithSecretId(with string) Option {
	return func(o *options) error {
		o.withSecretId = with
		return nil
	}
}
