package aidr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/crowdstrike/aidr-go/internal/apijson"
	"github.com/crowdstrike/aidr-go/internal/requestconfig"
	"github.com/crowdstrike/aidr-go/option"
	"github.com/crowdstrike/aidr-go/packages/param"
	"github.com/crowdstrike/aidr-go/packages/respjson"
)

// AIGuardService contains methods and other services that help with interacting
// with the AIDR API.
//
// Note, unlike clients, this service does not read variables from the environment
// automatically. You should not instantiate this service directly, and instead use
// the [NewAIGuardService] method instead.
type AIGuardService struct {
	Options     []option.RequestOption
	ServiceName string
}

// NewAIGuardService generates a new service that applies the given options to each
// request. These options are applied after the parent client's options (if there
// is one), and before any request-specific options.
func NewAIGuardService(opts ...option.RequestOption) (r AIGuardService) {
	r = AIGuardService{
		ServiceName: "aiguard",
	}
	r.Options = opts
	return
}

// Will retrieve the result, or will return 202 if the original request is still in
// progress
func (r *AIGuardService) GetAsyncRequest(ctx context.Context, requestID string, opts ...option.RequestOption) (res *AIGuardGetAsyncRequestResponse, err error) {
	opts = slices.Concat(r.Options, opts)
	opts = append(opts, option.WithServiceName(r.ServiceName))
	if requestID == "" {
		err = errors.New("missing required requestId parameter")
		return
	}
	path := fmt.Sprintf("request/%s", requestID)
	err = requestconfig.ExecuteNewRequest(ctx, http.MethodGet, path, nil, &res, opts...)
	return
}

// Analyze and redact content to avoid manipulation of the model, addition of
// malicious content, and other undesirable data transfers.
func (r *AIGuardService) GuardChatCompletions(ctx context.Context, body AIGuardGuardChatCompletionsParams, opts ...option.RequestOption) (res *AIGuardGuardChatCompletionsResponse, err error) {
	opts = slices.Concat(r.Options, opts)
	opts = append(opts, option.WithServiceName(r.ServiceName))
	path := "v1/guard_chat_completions"
	err = requestconfig.ExecuteNewRequest(ctx, http.MethodPost, path, body, &res, opts...)
	return
}

// Pangea standard response schema
type AIGuardGetAsyncRequestResponse struct {
	// A unique identifier assigned to each request made to the API. It is used to
	// track and identify a specific request and its associated data. The `request_id`
	// can be helpful for troubleshooting, auditing, and tracing the flow of requests
	// within the system. It allows users to reference and retrieve information related
	// to a particular request, such as the response, parameters, and raw data
	// associated with that specific request.
	//
	// ```
	// "request_id":"prq_x6fdiizbon6j3bsdvnpmwxsz2aan7fqd"
	// ```
	RequestID string `json:"request_id,required"`
	// The timestamp indicates the exact moment when a request is made to the API. It
	// represents the date and time at which the request was initiated by the client.
	// The `request_time` is useful for tracking and analyzing the timing of requests,
	// measuring response times, and monitoring performance metrics. It allows users to
	// determine the duration between the request initiation and the corresponding
	// response, aiding in the assessment of API performance and latency.
	//
	// ```
	// "request_time":"2022-09-21T17:24:33.105Z"
	// ```
	RequestTime time.Time `json:"request_time,required" format:"date-time"`
	// Duration it takes for the API to process a request and generate a response. It
	// represents the elapsed time from when the request is received by the API to when
	// the corresponding response is returned to the client.
	//
	// ```
	// "response_time":"2022-09-21T17:24:34.007Z"
	// ```
	ResponseTime time.Time `json:"response_time,required" format:"date-time"`
	// It represents the status or outcome of the API request made for IP information.
	// It indicates the current state or condition of the request and provides
	// information on the success or failure of the request.
	//
	// ```
	// "status":"success"
	// ```
	Status string `json:"status,required"`
	Result any    `json:"result"`
	// Provides a concise and brief overview of the purpose or primary objective of the
	// API endpoint. It serves as a high-level summary or description of the
	// functionality or feature offered by the endpoint.
	Summary string `json:"summary"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		RequestID    respjson.Field
		RequestTime  respjson.Field
		ResponseTime respjson.Field
		Status       respjson.Field
		Result       respjson.Field
		Summary      respjson.Field
		ExtraFields  map[string]respjson.Field
		raw          string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGetAsyncRequestResponse) RawJSON() string { return r.JSON.raw }
func (r *AIGuardGetAsyncRequestResponse) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponse struct {
	// A unique identifier assigned to each request made to the API. It is used to
	// track and identify a specific request and its associated data. The `request_id`
	// can be helpful for troubleshooting, auditing, and tracing the flow of requests
	// within the system. It allows users to reference and retrieve information related
	// to a particular request, such as the response, parameters, and raw data
	// associated with that specific request.
	//
	// ```
	// "request_id":"prq_x6fdiizbon6j3bsdvnpmwxsz2aan7fqd"
	// ```
	RequestID string `json:"request_id,required"`
	// The timestamp indicates the exact moment when a request is made to the API. It
	// represents the date and time at which the request was initiated by the client.
	// The `request_time` is useful for tracking and analyzing the timing of requests,
	// measuring response times, and monitoring performance metrics. It allows users to
	// determine the duration between the request initiation and the corresponding
	// response, aiding in the assessment of API performance and latency.
	//
	// ```
	// "request_time":"2022-09-21T17:24:33.105Z"
	// ```
	RequestTime time.Time `json:"request_time,required" format:"date-time"`
	// Duration it takes for the API to process a request and generate a response. It
	// represents the elapsed time from when the request is received by the API to when
	// the corresponding response is returned to the client.
	//
	// ```
	// "response_time":"2022-09-21T17:24:34.007Z"
	// ```
	ResponseTime time.Time                                 `json:"response_time,required" format:"date-time"`
	Result       AIGuardGuardChatCompletionsResponseResult `json:"result,required"`
	// It represents the status or outcome of the API request made for IP information.
	// It indicates the current state or condition of the request and provides
	// information on the success or failure of the request.
	//
	// ```
	// "status":"success"
	// ```
	//
	// Any of "Success".
	Status AIGuardGuardChatCompletionsResponseStatus `json:"status,required"`
	// Provides a concise and brief overview of the purpose or primary objective of the
	// API endpoint. It serves as a high-level summary or description of the
	// functionality or feature offered by the endpoint.
	Summary string `json:"summary"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		RequestID    respjson.Field
		RequestTime  respjson.Field
		ResponseTime respjson.Field
		Result       respjson.Field
		Status       respjson.Field
		Summary      respjson.Field
		ExtraFields  map[string]respjson.Field
		raw          string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponse) RawJSON() string { return r.JSON.raw }
func (r *AIGuardGuardChatCompletionsResponse) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResult struct {
	// Result of the policy analyzing and input prompt.
	Detectors AIGuardGuardChatCompletionsResponseResultDetectors `json:"detectors,required"`
	// Result of the recipe evaluating configured rules
	AccessRules any `json:"access_rules"`
	// Whether or not the prompt triggered a block detection.
	Blocked bool `json:"blocked"`
	// If an FPE redaction method returned results, this will be the context passed to
	// unredact.
	FpeContext string `json:"fpe_context" format:"base64"`
	// Updated structured prompt.
	GuardOutput any `json:"guard_output"`
	// The Policy that was used.
	Policy string `json:"policy"`
	// Whether or not the original input was transformed.
	Transformed bool `json:"transformed"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Detectors   respjson.Field
		AccessRules respjson.Field
		Blocked     respjson.Field
		FpeContext  respjson.Field
		GuardOutput respjson.Field
		Policy      respjson.Field
		Transformed respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResult) RawJSON() string { return r.JSON.raw }
func (r *AIGuardGuardChatCompletionsResponseResult) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Result of the policy analyzing and input prompt.
type AIGuardGuardChatCompletionsResponseResultDetectors struct {
	Code                     AIGuardGuardChatCompletionsResponseResultDetectorsCode                     `json:"code"`
	Competitors              AIGuardGuardChatCompletionsResponseResultDetectorsCompetitors              `json:"competitors"`
	ConfidentialAndPiiEntity AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntity `json:"confidential_and_pii_entity"`
	CustomEntity             AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntity             `json:"custom_entity"`
	Language                 AIGuardGuardChatCompletionsResponseResultDetectorsLanguage                 `json:"language"`
	MaliciousEntity          AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntity          `json:"malicious_entity"`
	MaliciousPrompt          AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPrompt          `json:"malicious_prompt"`
	SecretAndKeyEntity       AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntity       `json:"secret_and_key_entity"`
	Topic                    AIGuardGuardChatCompletionsResponseResultDetectorsTopic                    `json:"topic"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Code                     respjson.Field
		Competitors              respjson.Field
		ConfidentialAndPiiEntity respjson.Field
		CustomEntity             respjson.Field
		Language                 respjson.Field
		MaliciousEntity          respjson.Field
		MaliciousPrompt          respjson.Field
		SecretAndKeyEntity       respjson.Field
		Topic                    respjson.Field
		ExtraFields              map[string]respjson.Field
		raw                      string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectors) RawJSON() string { return r.JSON.raw }
func (r *AIGuardGuardChatCompletionsResponseResultDetectors) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsCode struct {
	// Details about the detected code.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsCodeData `json:"data"`
	// Whether or not the Code was detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCode) RawJSON() string { return r.JSON.raw }
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCode) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected code.
type AIGuardGuardChatCompletionsResponseResultDetectorsCodeData struct {
	// The action taken by this Detector
	Action   string `json:"action"`
	Language string `json:"language"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Language    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCodeData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCodeData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsCompetitors struct {
	// Details about the detected entities.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsCompetitorsData `json:"data"`
	// Whether or not the Competitors were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCompetitors) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCompetitors) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected entities.
type AIGuardGuardChatCompletionsResponseResultDetectorsCompetitorsData struct {
	// The action taken by this Detector
	Action string `json:"action"`
	// Detected entities.
	Entities []string `json:"entities"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Entities    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCompetitorsData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCompetitorsData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntity struct {
	// Details about the detected entities.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityData `json:"data"`
	// Whether or not the PII Entities were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected entities.
type AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityData struct {
	// Detected redaction rules.
	Entities []AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityDataEntity `json:"entities"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Entities    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityDataEntity struct {
	// The action taken on this Entity
	Action   string `json:"action,required"`
	Type     string `json:"type,required"`
	Value    string `json:"value,required"`
	StartPos int64  `json:"start_pos"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Type        respjson.Field
		Value       respjson.Field
		StartPos    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityDataEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsConfidentialAndPiiEntityDataEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntity struct {
	// Details about the detected entities.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityData `json:"data"`
	// Whether or not the Custom Entities were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected entities.
type AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityData struct {
	// Detected redaction rules.
	Entities []AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityDataEntity `json:"entities"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Entities    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityDataEntity struct {
	// The action taken on this Entity
	Action   string `json:"action,required"`
	Type     string `json:"type,required"`
	Value    string `json:"value,required"`
	StartPos int64  `json:"start_pos"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Type        respjson.Field
		Value       respjson.Field
		StartPos    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityDataEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsCustomEntityDataEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsLanguage struct {
	// Details about the detected languages.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsLanguageData `json:"data"`
	// Whether or not the Languages were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsLanguage) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsLanguage) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected languages.
type AIGuardGuardChatCompletionsResponseResultDetectorsLanguageData struct {
	// The action taken by this Detector
	Action   string `json:"action"`
	Language string `json:"language"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Language    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsLanguageData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsLanguageData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntity struct {
	// Details about the detected entities.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityData `json:"data"`
	// Whether or not the Malicious Entities were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected entities.
type AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityData struct {
	// Detected harmful items.
	Entities []AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityDataEntity `json:"entities"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Entities    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityDataEntity struct {
	Type     string `json:"type,required"`
	Value    string `json:"value,required"`
	Raw      any    `json:"raw"`
	StartPos int64  `json:"start_pos"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Type        respjson.Field
		Value       respjson.Field
		Raw         respjson.Field
		StartPos    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityDataEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousEntityDataEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPrompt struct {
	// Details about the analyzers.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptData `json:"data"`
	// Whether or not the Malicious Prompt was detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPrompt) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPrompt) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the analyzers.
type AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptData struct {
	// The action taken by this Detector
	Action string `json:"action"`
	// Triggered prompt injection analyzers.
	AnalyzerResponses []AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptDataAnalyzerResponse `json:"analyzer_responses"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action            respjson.Field
		AnalyzerResponses respjson.Field
		ExtraFields       map[string]respjson.Field
		raw               string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptDataAnalyzerResponse struct {
	Analyzer   string  `json:"analyzer,required"`
	Confidence float64 `json:"confidence,required"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Analyzer    respjson.Field
		Confidence  respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptDataAnalyzerResponse) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsMaliciousPromptDataAnalyzerResponse) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntity struct {
	// Details about the detected entities.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityData `json:"data"`
	// Whether or not the Secret Entities were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected entities.
type AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityData struct {
	// Detected redaction rules.
	Entities []AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityDataEntity `json:"entities"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Entities    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityDataEntity struct {
	// The action taken on this Entity
	Action   string `json:"action,required"`
	Type     string `json:"type,required"`
	Value    string `json:"value,required"`
	StartPos int64  `json:"start_pos"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Type        respjson.Field
		Value       respjson.Field
		StartPos    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityDataEntity) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsSecretAndKeyEntityDataEntity) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsTopic struct {
	// Details about the detected topics.
	Data AIGuardGuardChatCompletionsResponseResultDetectorsTopicData `json:"data"`
	// Whether or not the Topics were detected.
	Detected bool `json:"detected"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Data        respjson.Field
		Detected    respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsTopic) RawJSON() string { return r.JSON.raw }
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsTopic) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// Details about the detected topics.
type AIGuardGuardChatCompletionsResponseResultDetectorsTopicData struct {
	// The action taken by this Detector
	Action string `json:"action"`
	// List of topics detected
	Topics []AIGuardGuardChatCompletionsResponseResultDetectorsTopicDataTopic `json:"topics"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Action      respjson.Field
		Topics      respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsTopicData) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsTopicData) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

type AIGuardGuardChatCompletionsResponseResultDetectorsTopicDataTopic struct {
	Confidence float64 `json:"confidence,required"`
	Topic      string  `json:"topic,required"`
	// JSON contains metadata for fields, check presence with [respjson.Field.Valid].
	JSON struct {
		Confidence  respjson.Field
		Topic       respjson.Field
		ExtraFields map[string]respjson.Field
		raw         string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r AIGuardGuardChatCompletionsResponseResultDetectorsTopicDataTopic) RawJSON() string {
	return r.JSON.raw
}
func (r *AIGuardGuardChatCompletionsResponseResultDetectorsTopicDataTopic) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// It represents the status or outcome of the API request made for IP information.
// It indicates the current state or condition of the request and provides
// information on the success or failure of the request.
//
// ```
// "status":"success"
// ```
type AIGuardGuardChatCompletionsResponseStatus string

const (
	AIGuardGuardChatCompletionsResponseStatusSuccess AIGuardGuardChatCompletionsResponseStatus = "Success"
)

type AIGuardGuardChatCompletionsParams struct {
	// 'messages' contains Prompt content and role array in JSON format. The `content`
	// is the multimodel text or image input that will be analyzed. Additional
	// properties such as 'tools' may be provided for analysis.
	GuardInput any `json:"guard_input,omitzero,required"`
	// Id of source application/agent
	AppID param.Opt[string] `json:"app_id,omitzero"`
	// (AIDR) collector instance id.
	CollectorInstanceID param.Opt[string] `json:"collector_instance_id,omitzero"`
	// Underlying LLM. Example: 'OpenAI'.
	LlmProvider param.Opt[string] `json:"llm_provider,omitzero"`
	// Model used to perform the event. Example: 'gpt'.
	Model param.Opt[string] `json:"model,omitzero"`
	// Model version used to perform the event. Example: '3.5'.
	ModelVersion param.Opt[string] `json:"model_version,omitzero"`
	// IP address of user or app or agent.
	SourceIP param.Opt[string] `json:"source_ip,omitzero"`
	// Location of user or app or agent.
	SourceLocation param.Opt[string] `json:"source_location,omitzero"`
	// For gateway-like integrations with multi-tenant support.
	TenantID param.Opt[string] `json:"tenant_id,omitzero"`
	// User/Service account id/service account
	UserID param.Opt[string] `json:"user_id,omitzero"`
	// (AIDR) Event Type.
	//
	// Any of "input", "output", "tool_input", "tool_output", "tool_listing".
	EventType AIGuardGuardChatCompletionsParamsEventType `json:"event_type,omitzero"`
	// (AIDR) Logging schema.
	ExtraInfo AIGuardGuardChatCompletionsParamsExtraInfo `json:"extra_info,omitzero"`
	paramObj
}

func (r AIGuardGuardChatCompletionsParams) MarshalJSON() (data []byte, err error) {
	type shadow AIGuardGuardChatCompletionsParams
	return param.MarshalObject(r, (*shadow)(&r))
}
func (r *AIGuardGuardChatCompletionsParams) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// (AIDR) Event Type.
type AIGuardGuardChatCompletionsParamsEventType string

const (
	AIGuardGuardChatCompletionsParamsEventTypeInput       AIGuardGuardChatCompletionsParamsEventType = "input"
	AIGuardGuardChatCompletionsParamsEventTypeOutput      AIGuardGuardChatCompletionsParamsEventType = "output"
	AIGuardGuardChatCompletionsParamsEventTypeToolInput   AIGuardGuardChatCompletionsParamsEventType = "tool_input"
	AIGuardGuardChatCompletionsParamsEventTypeToolOutput  AIGuardGuardChatCompletionsParamsEventType = "tool_output"
	AIGuardGuardChatCompletionsParamsEventTypeToolListing AIGuardGuardChatCompletionsParamsEventType = "tool_listing"
)

// (AIDR) Logging schema.
type AIGuardGuardChatCompletionsParamsExtraInfo struct {
	// The group of subject actor.
	ActorGroup param.Opt[string] `json:"actor_group,omitzero"`
	// Name of subject actor/service account.
	ActorName param.Opt[string] `json:"actor_name,omitzero"`
	// The group of source application/agent.
	AppGroup param.Opt[string] `json:"app_group,omitzero"`
	// Name of source application/agent.
	AppName param.Opt[string] `json:"app_name,omitzero"`
	// Version of the source application/agent.
	AppVersion param.Opt[string] `json:"app_version,omitzero"`
	// Geographic region or data center.
	SourceRegion param.Opt[string] `json:"source_region,omitzero"`
	// Sub tenant of the user or organization
	SubTenant param.Opt[string] `json:"sub_tenant,omitzero"`
	// Each item groups tools for a given MCP server.
	McpTools    []AIGuardGuardChatCompletionsParamsExtraInfoMcpTool `json:"mcp_tools,omitzero"`
	ExtraFields map[string]any                                      `json:"-"`
	paramObj
}

func (r AIGuardGuardChatCompletionsParamsExtraInfo) MarshalJSON() (data []byte, err error) {
	type shadow AIGuardGuardChatCompletionsParamsExtraInfo
	return param.MarshalWithExtras(r, (*shadow)(&r), r.ExtraFields)
}
func (r *AIGuardGuardChatCompletionsParamsExtraInfo) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}

// The properties ServerName, Tools are required.
type AIGuardGuardChatCompletionsParamsExtraInfoMcpTool struct {
	// MCP server name
	ServerName string   `json:"server_name,required"`
	Tools      []string `json:"tools,omitzero,required"`
	paramObj
}

func (r AIGuardGuardChatCompletionsParamsExtraInfoMcpTool) MarshalJSON() (data []byte, err error) {
	type shadow AIGuardGuardChatCompletionsParamsExtraInfoMcpTool
	return param.MarshalObject(r, (*shadow)(&r))
}
func (r *AIGuardGuardChatCompletionsParamsExtraInfoMcpTool) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}
