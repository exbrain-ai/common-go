package validation

import (
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// Sanitizer provides input sanitization utilities
type Sanitizer struct {
	htmlPolicy *bluemonday.Policy
}

// NewSanitizer creates a new sanitizer instance
func NewSanitizer() *Sanitizer {
	// Create a strict policy that removes all HTML tags
	policy := bluemonday.StrictPolicy()

	// Allow only basic text formatting for specific use cases
	// This can be customized based on requirements
	policy.AllowElements("b", "i", "em", "strong")

	return &Sanitizer{
		htmlPolicy: policy,
	}
}

// SanitizeString sanitizes a string input by removing HTML tags and trimming whitespace
func (s *Sanitizer) SanitizeString(input string) string {
	if input == "" {
		return ""
	}

	// Remove HTML tags
	sanitized := s.htmlPolicy.Sanitize(input)

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}

// SanitizeName sanitizes a name input (more restrictive)
func (s *Sanitizer) SanitizeName(input string) string {
	if input == "" {
		return ""
	}

	// Remove all HTML tags
	sanitized := s.htmlPolicy.Sanitize(input)

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	// Remove any remaining special characters that might be dangerous
	sanitized = strings.ReplaceAll(sanitized, "<", "")
	sanitized = strings.ReplaceAll(sanitized, ">", "")
	sanitized = strings.ReplaceAll(sanitized, "&", "")
	sanitized = strings.ReplaceAll(sanitized, "\"", "")
	sanitized = strings.ReplaceAll(sanitized, "'", "")
	sanitized = strings.ReplaceAll(sanitized, "/", "")
	sanitized = strings.ReplaceAll(sanitized, "\\", "")

	return sanitized
}

// SanitizeTitle sanitizes a title input
func (s *Sanitizer) SanitizeTitle(input string) string {
	if input == "" {
		return ""
	}

	// Remove all HTML tags
	sanitized := s.htmlPolicy.Sanitize(input)

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	// Remove any remaining special characters that might be dangerous
	sanitized = strings.ReplaceAll(sanitized, "<", "")
	sanitized = strings.ReplaceAll(sanitized, ">", "")
	sanitized = strings.ReplaceAll(sanitized, "&", "")
	sanitized = strings.ReplaceAll(sanitized, "\"", "")
	sanitized = strings.ReplaceAll(sanitized, "'", "")
	sanitized = strings.ReplaceAll(sanitized, "/", "")
	sanitized = strings.ReplaceAll(sanitized, "\\", "")

	return sanitized
}

// SanitizeHTML sanitizes HTML content (allows some HTML tags)
func (s *Sanitizer) SanitizeHTML(input string) string {
	if input == "" {
		return ""
	}

	// Use the policy to sanitize HTML
	sanitized := s.htmlPolicy.Sanitize(input)

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}
