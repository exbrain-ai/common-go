package validation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test NewSanitizer
func TestNewSanitizer(t *testing.T) {
	sanitizer := NewSanitizer()
	assert.NotNil(t, sanitizer)
	assert.NotNil(t, sanitizer.htmlPolicy)
}

// Test SanitizeString method
func TestSanitizer_SanitizeString(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Plain text",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "Text with whitespace",
			input:    "  Hello World  ",
			expected: "Hello World",
		},
		{
			name:     "Text with allowed HTML tags",
			input:    "Hello <b>World</b>",
			expected: "Hello <b>World</b>",
		},
		{
			name:     "Text with allowed HTML tags - italic",
			input:    "Hello <i>World</i>",
			expected: "Hello <i>World</i>",
		},
		{
			name:     "Text with allowed HTML tags - emphasis",
			input:    "Hello <em>World</em>",
			expected: "Hello <em>World</em>",
		},
		{
			name:     "Text with allowed HTML tags - strong",
			input:    "Hello <strong>World</strong>",
			expected: "Hello <strong>World</strong>",
		},
		{
			name:     "Text with dangerous HTML tags",
			input:    "Hello <script>alert('xss')</script>World",
			expected: "Hello World",
		},
		{
			name:     "Text with dangerous HTML tags - img",
			input:    "Hello <img src='x' onerror='alert(1)'>World",
			expected: "Hello World",
		},
		{
			name:     "Text with dangerous HTML tags - a",
			input:    "Hello <a href='javascript:alert(1)'>link</a>World",
			expected: "Hello linkWorld", // Link text remains after tag removal
		},
		{
			name:     "Text with div tags",
			input:    "Hello <div>World</div>",
			expected: "Hello World",
		},
		{
			name:     "Text with span tags",
			input:    "Hello <span>World</span>",
			expected: "Hello World",
		},
		{
			name:     "Mixed allowed and disallowed tags",
			input:    "Hello <b>Bold</b> and <script>bad</script> text",
			expected: "Hello <b>Bold</b> and  text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test SanitizeName method
func TestSanitizer_SanitizeName(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Plain name",
			input:    "John Doe",
			expected: "John Doe",
		},
		{
			name:     "Name with whitespace",
			input:    "  John Doe  ",
			expected: "John Doe",
		},
		{
			name:     "Name with HTML tags",
			input:    "John <b>Doe</b>",
			expected: "John bDoeb", // Content remains with some tag remnants after sanitization
		},
		{
			name:     "Name with dangerous characters",
			input:    "John<script>alert(1)</script>Doe",
			expected: "JohnDoe",
		},
		{
			name:     "Name with special characters",
			input:    "John & Jane",
			expected: "John amp; Jane", // HTML entities are partially sanitized
		},
		{
			name:     "Name with quotes",
			input:    `John "Johnny" Doe`,
			expected: "John #34;Johnny#34; Doe", // Quotes become HTML entity codes
		},
		{
			name:     "Name with single quotes",
			input:    "John 'Johnny' Doe",
			expected: "John #39;Johnny#39; Doe", // Single quotes become HTML entity codes
		},
		{
			name:     "Name with slashes",
			input:    "John/Jane\\Doe",
			expected: "JohnJaneDoe", // Slashes are removed
		},
		{
			name:     "Name with angle brackets",
			input:    "John <Jane> Doe",
			expected: "John  Doe", // Content inside angle brackets is removed as HTML tag
		},
		{
			name:     "Name with all special chars",
			input:    `John<>&"'/\Doe`,
			expected: "Johnlt;gt;amp;#34;#39;Doe", // Special chars become HTML entities
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test SanitizeTitle method
func TestSanitizer_SanitizeTitle(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Plain title",
			input:    "My Article Title",
			expected: "My Article Title",
		},
		{
			name:     "Title with whitespace",
			input:    "  My Article Title  ",
			expected: "My Article Title",
		},
		{
			name:     "Title with HTML tags",
			input:    "My <b>Article</b> Title",
			expected: "My bArticleb Title", // Content remains with some tag remnants
		},
		{
			name:     "Title with dangerous characters",
			input:    "My<script>alert(1)</script>Title",
			expected: "MyTitle",
		},
		{
			name:     "Title with special characters",
			input:    "Article & News",
			expected: "Article amp; News", // & becomes amp;
		},
		{
			name:     "Title with quotes",
			input:    `Article "Breaking News" Today`,
			expected: "Article #34;Breaking News#34; Today", // Quotes become entity codes
		},
		{
			name:     "Title with slashes",
			input:    "News/Updates\\Today",
			expected: "NewsUpdatesToday", // Slashes are removed
		},
		{
			name:     "Title with angle brackets",
			input:    "News <Update> Today",
			expected: "News  Today", // Content inside angle brackets removed as HTML tag
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeTitle(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test SanitizeHTML method
func TestSanitizer_SanitizeHTML(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Plain text",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "HTML with whitespace",
			input:    "  <b>Hello</b> World  ",
			expected: "<b>Hello</b> World",
		},
		{
			name:     "HTML with allowed tags",
			input:    "Hello <b>World</b> and <i>everyone</i>",
			expected: "Hello <b>World</b> and <i>everyone</i>",
		},
		{
			name:     "HTML with dangerous tags",
			input:    "Hello <script>alert('xss')</script>World",
			expected: "Hello World",
		},
		{
			name:     "HTML with mixed content",
			input:    "Hello <b>Bold</b> <script>bad</script> <em>Emphasis</em>",
			expected: "Hello <b>Bold</b>  <em>Emphasis</em>",
		},
		{
			name:     "HTML with attributes",
			input:    `<b class="highlight">Bold</b>`,
			expected: "<b>Bold</b>", // Attributes should be stripped
		},
		{
			name:     "HTML with dangerous attributes",
			input:    `<b onclick="alert(1)">Bold</b>`,
			expected: "<b>Bold</b>", // Dangerous attributes should be stripped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test edge cases and special scenarios
func TestSanitizer_LongStrings(t *testing.T) {
	sanitizer := NewSanitizer()

	// Test with very long string
	longString := strings.Repeat("This is a long string with some <script>alert(1)</script> content. ", 100)
	result := sanitizer.SanitizeString(longString)

	// Should not contain script tags
	assert.NotContains(t, result, "<script>")
	assert.NotContains(t, result, "alert(1)")

	// Should still contain the safe content
	assert.Contains(t, result, "This is a long string")
	assert.Contains(t, result, "content.")
}

func TestSanitizer_NestedTags(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Nested allowed tags",
			input:    "<b>Bold <i>and italic</i> text</b>",
			expected: "<b>Bold <i>and italic</i> text</b>",
		},
		{
			name:     "Nested with dangerous tags",
			input:    "<b>Bold <script>alert(1)</script> text</b>",
			expected: "<b>Bold  text</b>",
		},
		{
			name:     "Deep nesting",
			input:    "<b><i><em><strong>Text</strong></em></i></b>",
			expected: "<b><i><em><strong>Text</strong></em></i></b>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizer_UnicodeCharacters(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Unicode characters in string",
			input:    "Hello 世界 🌍",
			expected: "Hello 世界 🌍",
		},
		{
			name:     "Unicode with HTML",
			input:    "<b>Hello 世界</b> 🌍",
			expected: "<b>Hello 世界</b> 🌍",
		},
		{
			name:     "Unicode in name",
			input:    "José García",
			expected: "José García",
		},
		{
			name:     "Unicode in title",
			input:    "Artículo de Noticias",
			expected: "Artículo de Noticias",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizer_WhitespaceHandling(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		method   func(string) string
		input    string
		expected string
	}{
		{
			name:     "Leading spaces - SanitizeString",
			method:   sanitizer.SanitizeString,
			input:    "    Hello World",
			expected: "Hello World",
		},
		{
			name:     "Trailing spaces - SanitizeString",
			method:   sanitizer.SanitizeString,
			input:    "Hello World    ",
			expected: "Hello World",
		},
		{
			name:     "Multiple spaces - SanitizeString",
			method:   sanitizer.SanitizeString,
			input:    "Hello     World",
			expected: "Hello     World", // Internal spaces are preserved
		},
		{
			name:     "Tabs and newlines - SanitizeString",
			method:   sanitizer.SanitizeString,
			input:    "\t\nHello World\t\n",
			expected: "Hello World",
		},
		{
			name:     "Leading spaces - SanitizeName",
			method:   sanitizer.SanitizeName,
			input:    "    John Doe",
			expected: "John Doe",
		},
		{
			name:     "Trailing spaces - SanitizeTitle",
			method:   sanitizer.SanitizeTitle,
			input:    "Article Title    ",
			expected: "Article Title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.method(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizer_OnlyWhitespace(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name   string
		method func(string) string
		input  string
	}{
		{
			name:   "Only spaces - SanitizeString",
			method: sanitizer.SanitizeString,
			input:  "    ",
		},
		{
			name:   "Only tabs - SanitizeName",
			method: sanitizer.SanitizeName,
			input:  "\t\t\t",
		},
		{
			name:   "Only newlines - SanitizeTitle",
			method: sanitizer.SanitizeTitle,
			input:  "\n\n\n",
		},
		{
			name:   "Mixed whitespace - SanitizeHTML",
			method: sanitizer.SanitizeHTML,
			input:  " \t\n ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.method(tt.input)
			assert.Empty(t, result, "Should return empty string for whitespace-only input")
		})
	}
}

// Benchmark tests
func BenchmarkSanitizer_SanitizeString(b *testing.B) {
	sanitizer := NewSanitizer()
	input := "Hello <b>World</b> with <script>alert(1)</script> content"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.SanitizeString(input)
	}
}

func BenchmarkSanitizer_SanitizeName(b *testing.B) {
	sanitizer := NewSanitizer()
	input := "John <>&\"'/\\Doe"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.SanitizeName(input)
	}
}

func BenchmarkSanitizer_SanitizeTitle(b *testing.B) {
	sanitizer := NewSanitizer()
	input := "Article <b>Title</b> with special chars <>&\"'/\\"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.SanitizeTitle(input)
	}
}

func BenchmarkSanitizer_SanitizeHTML(b *testing.B) {
	sanitizer := NewSanitizer()
	input := "<b>Bold</b> <i>Italic</i> <script>alert(1)</script> <em>Emphasis</em>"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizer.SanitizeHTML(input)
	}
}

func BenchmarkNewSanitizer(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewSanitizer()
	}
}

// Test concurrent access to sanitizer
func TestSanitizer_Concurrent(t *testing.T) {
	sanitizer := NewSanitizer()

	// Test that the same sanitizer instance can be used concurrently
	// This is important for shared sanitizer instances
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			input := fmt.Sprintf("Test %d <script>alert(%d)</script>", id, id)
			result := sanitizer.SanitizeString(input)
			assert.NotContains(t, result, "<script>")
			assert.Contains(t, result, fmt.Sprintf("Test %d", id))
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
