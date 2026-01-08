package aidr

import (
	"time"

	"github.com/crowdstrike/aidr-go/internal/apijson"
	"github.com/crowdstrike/aidr-go/packages/respjson"
)

// Pangea standard response schema
type PangeaResponse struct {
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
		Summary      respjson.Field
		ExtraFields  map[string]respjson.Field
		raw          string
	} `json:"-"`
}

// Returns the unmodified JSON received from the API
func (r PangeaResponse) RawJSON() string { return r.JSON.raw }

func (r *PangeaResponse) UnmarshalJSON(data []byte) error {
	return apijson.UnmarshalRoot(data, r)
}
