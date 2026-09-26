package fingerprint

import "context"

type activityKey struct{}

// RecordActivity records transport progress without keeping raw model output.
// The callback updates in-memory snapshots; durable accounting remains per request.
func RecordActivity(ctx context.Context, bytes int) {
	if record, ok := ctx.Value(activityKey{}).(func(int)); ok && bytes > 0 {
		record(bytes)
	}
}
