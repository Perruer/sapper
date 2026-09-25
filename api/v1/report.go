package v1

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	service "github.com/Perruer/sapper/gen/api/v1"
	"github.com/Perruer/sapper/pkg/report"
	"github.com/Perruer/sapper/pkg/tools/ingest"
)

func (s *Service) IngestKEV(ctx context.Context, req *connect.Request[service.IngestDataRequest]) (*connect.Response[service.IngestDataResponse], error) {
	count, err := ingest.KEV(s.storage, req.Msg.Data)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to ingest the KEV catalog: %w", err))
	}
	return connect.NewResponse(&service.IngestDataResponse{Count: int64(count)}), nil
}

func (s *Service) IngestEPSS(ctx context.Context, req *connect.Request[service.IngestDataRequest]) (*connect.Response[service.IngestDataResponse], error) {
	count, err := ingest.EPSS(s.storage, req.Msg.Data)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to ingest EPSS scores: %w", err))
	}
	return connect.NewResponse(&service.IngestDataResponse{Count: int64(count)}), nil
}

func (s *Service) IngestVEX(ctx context.Context, req *connect.Request[service.IngestDataRequest]) (*connect.Response[service.IngestDataResponse], error) {
	count, err := ingest.VEX(s.storage, req.Msg.Data)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to ingest the VEX document: %w", err))
	}
	return connect.NewResponse(&service.IngestDataResponse{Count: int64(count)}), nil
}

func (s *Service) Report(ctx context.Context, req *connect.Request[service.ReportRequest]) (*connect.Response[service.ReportResponse], error) {
	findings, err := report.Build(s.storage, report.Options{
		Vulnerability: req.Msg.Vulnerability,
		KEVOnly:       req.Msg.KevOnly,
		MinEPSS:       req.Msg.MinEpss,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build the report: %w", err)
	}
	resp := &service.ReportResponse{Findings: make([]*service.Finding, 0, len(findings))}
	for _, f := range findings {
		resp.Findings = append(resp.Findings, findingToProto(f))
	}
	return connect.NewResponse(resp), nil
}

func findingToProto(f report.Finding) *service.Finding {
	out := &service.Finding{
		Id:         f.ID,
		Aliases:    f.Aliases,
		Summary:    f.Summary,
		Severity:   f.Severity,
		Packages:   f.Packages,
		Products:   productsToProto(f.Products),
		Suppressed: productsToProto(f.Suppressed),
	}
	if f.KEV != nil {
		out.Kev = &service.KEVEntry{
			CveId:                      f.KEV.CVEID,
			VendorProject:              f.KEV.VendorProject,
			Product:                    f.KEV.Product,
			VulnerabilityName:          f.KEV.VulnerabilityName,
			DateAdded:                  f.KEV.DateAdded,
			ShortDescription:           f.KEV.ShortDescription,
			RequiredAction:             f.KEV.RequiredAction,
			DueDate:                    f.KEV.DueDate,
			KnownRansomwareCampaignUse: f.KEV.KnownRansomwareCampaignUse,
		}
	}
	if f.EPSS != nil {
		out.Epss = &service.EPSSScore{Epss: f.EPSS.EPSS, Percentile: f.EPSS.Percentile, Date: f.EPSS.Date}
	}
	return out
}

func productsToProto(products []report.Product) []*service.ProductImpact {
	out := make([]*service.ProductImpact, 0, len(products))
	for _, p := range products {
		impact := &service.ProductImpact{Name: p.Name, Path: p.Path}
		if p.VEX != nil {
			impact.Vex = &service.VEXStatement{
				Status:          p.VEX.Status,
				Justification:   p.VEX.Justification,
				ImpactStatement: p.VEX.ImpactStatement,
				ActionStatement: p.VEX.ActionStatement,
				Timestamp:       p.VEX.Timestamp,
			}
		}
		out = append(out, impact)
	}
	return out
}
