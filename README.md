# CrowdStrike AIDR Go SDK

Go SDK for CrowdStrike AIDR.

## Installation

```bash
go get github.com/crowdstrike/aidr-go
```

```go
import (
	"github.com/crowdstrike/aidr-go" // Imported as `aidr`.
)
```

## Requirements

Go v1.24 or higher.

## Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/crowdstrike/aidr-go"
    "github.com/crowdstrike/aidr-go/option"
)

func main() {
    ctx := context.Background()

    client := aidr.NewClient(
        option.WithBaseURLTemplate("https://api.eu-1.crowdstrike.com/aidr/{SERVICE_NAME}"),
        option.WithToken("your-api-token"),
    )

    params := aidr.AIGuardGuardChatCompletionsParams{
        GuardInput: map[string]any{
            "messages": []any{
                map[string]any{
                    "role":    "user",
                    "content": "Your prompt here",
                },
            },
        },
        EventType: aidr.AIGuardGuardChatCompletionsParamsEventTypeInput,
    }

    response, err := client.AIGuard.GuardChatCompletions(ctx, params)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Request ID: %s\n", response.RequestID)
    fmt.Printf("Status: %s\n", response.Status)
    fmt.Printf("Blocked: %v\n", response.Result.Blocked)
}
```

### Request options

This library uses the functional options pattern. Functions defined in the
`option` package return a `RequestOption`, which is a closure that mutates a
`RequestConfig`. These options can be supplied to the client or at individual
requests. For example:

```go
client := aidr.NewClient(
	// Add a header to every request made by the client.
	option.WithHeader("X-Some-Header", "custom_header_info"),
)

client.AIGuard.GuardChatCompletions(context.TODO(), ...,
	// Override the header.
	option.WithHeader("X-Some-Header", "some_other_custom_header_info")),
)
```

The request option `option.WithDebugLog(nil)` may be helpful while debugging.

See the [full list of request options](https://pkg.go.dev/github.com/crowdstrike/aidr-go/option).

### Retries

Certain errors will be automatically retried 2 times by default, with a short
exponential backoff. We retry by default all connection errors, HTTP/408,
HTTP/409, HTTP/429, and HTTP/5xx errors.

Use the `WithMaxRetries` option to configure or disable this:

```go
// Configure the default for all requests.
client := aidr.NewClient(
	option.WithMaxRetries(0), // Default is 2.
)

// Override per-request.
client.AIGuard.GuardChatCompletions(
	context.TODO(),
	aidr.AIGuardGuardChatCompletionsParams{
		GuardInput: map[string]any{
			"messages": []any{
				map[string]any{
					"role":    "user",
					"content": "Your prompt here",
				},
			},
		},
		EventType: aidr.AIGuardGuardChatCompletionsParamsEventTypeInput,
	},
	option.WithMaxRetries(5),
)
```

### Timeouts

Requests do not time out by default; use context to configure a timeout for a
request lifecycle.

Note that if a request is [retried](#retries), the context timeout does not
start over. To set a per-retry timeout, use `option.WithRequestTimeout()`.

```go
// This sets the timeout for the request, including all the retries.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

client.AIGuard.GuardChatCompletions(
	ctx,
	aidr.AIGuardGuardChatCompletionsParams{
		GuardInput: map[string]any{
			"messages": []any{
				map[string]any{
					"role":    "user",
					"content": "Your prompt here",
				},
			},
		},
		EventType: aidr.AIGuardGuardChatCompletionsParamsEventTypeInput,
	},
	// This sets the per-retry timeout.
	option.WithRequestTimeout(20*time.Second),
)
```

### Errors

When the API returns a non-success status code, an error with type `*aidr.Error`
is returned. This contains the `StatusCode`, `*http.Request`, and
`*http.Response` values of the request, as well as the JSON of the error body
(much like other response objects in the SDK).

To handle errors, it's recommended to use the `errors.As` pattern:

```go
_, err := client.AIGuard.GuardChatCompletions(context.TODO(), aidr.AIGuardGuardChatCompletionsParams{
	GuardInput: map[string]any{
		"messages": []any{
			map[string]any{
				"role":    "user",
				"content": "Your prompt here",
			},
		},
	},
})
if err != nil {
	var apierr *aidr.Error
	if errors.As(err, &apierr) {
		println(string(apierr.DumpRequest(true)))  // Prints the serialized HTTP request.
		println(string(apierr.DumpResponse(true))) // Prints the serialized HTTP response.
	}
	panic(err.Error()) // GET "/v1/guard_chat_completions": 400 Bad Request { ... }
}
```

When other errors occur, they are returned unwrapped; for example, if HTTP
transport fails, you might receive `*url.Error` wrapping `*net.OpError`.
