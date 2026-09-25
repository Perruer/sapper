package helpers

import (
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

// NewTable returns a table writer that never wraps cell text, like the tables the CLI printed
// with tablewriter v0. With rowLines it also draws a line between rows.
func NewTable(w io.Writer, rowLines bool) *tablewriter.Table {
	opts := []tablewriter.Option{
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithHeaderAutoWrap(tw.WrapNone),
	}
	if rowLines {
		opts = append(opts, tablewriter.WithRendition(tw.Rendition{
			Settings: tw.Settings{Separators: tw.Separators{BetweenRows: tw.On}},
		}))
	}
	return tablewriter.NewTable(w, opts...)
}
