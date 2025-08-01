package sonar_client

import (
	"html/template"
	"io"
	"path/filepath"
)

func RenderTemplate(writer io.Writer, name string, data interface{}) error {
	// Parse template
	tmpl, err := template.ParseFiles(filepath.Join("templates", name))
	if err != nil {
		return err
	}

	return tmpl.Execute(writer, data)
}

func RenderHtmlHead(writer io.Writer) error {
	return RenderTemplate(writer, "head_p.gohtml", nil)
}

func RenderHtmlTail(writer io.Writer) error {
	return RenderTemplate(writer, "tail_p.gohtml", nil)
}
