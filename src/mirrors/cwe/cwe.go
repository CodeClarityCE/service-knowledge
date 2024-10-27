package cwe

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// Write a function that downloads an XML file from the CWE website
func downloadFile(url string) (knowledge.CWEListImport, error) {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err)
		return knowledge.CWEListImport{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return knowledge.CWEListImport{}, err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		log.Println(err)
		return knowledge.CWEListImport{}, err
	}

	// There is only one file in the zip archive
	zipFile := zipReader.File[0]
	// fmt.Println("Reading file:", zipFile.Name)
	unzippedFileBytes, err := readZipFile(zipFile)
	if err != nil {
		log.Println(err)
		return knowledge.CWEListImport{}, err
	}

	var result knowledge.CWEListImport
	err = xml.Unmarshal(unzippedFileBytes, &result)
	if err != nil {
		log.Println(err)
		return knowledge.CWEListImport{}, err
	}
	return result, nil

}

func cleanString(text string) string {
	pattern := regexp.MustCompile(`\s+`)
	res := pattern.ReplaceAllString(text, " ")
	res = strings.ReplaceAll(res, "\n", "")
	res = strings.ReplaceAll(res, "\t", "")
	res = strings.ReplaceAll(res, "\"", "")
	res = strings.TrimSpace(res)
	return res
}

func downloadCWEs() ([]knowledge.CWEEntry, error) {
	res, err := downloadFile("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	weaknessMap := map[string]knowledge.WeaknessCWE{}
	categoryMap := map[string]knowledge.Category{}

	for _, weakness := range res.Weaknesses.Weaknesses {
		weaknessMap[weakness.ID] = weakness
	}
	for _, category := range res.Categories.Categories {
		categoryMap[category.ID] = category
	}
	for _, category := range res.Categories.Categories {
		for _, member := range category.Relationships.HasMember {
			if member.CWEID != "" {
				if weakness, ok := weaknessMap[member.CWEID]; ok {
					weakness.MemberShips = append(weakness.MemberShips, category.ID)
					weaknessMap[member.CWEID] = weakness
				}
			}
		}
	}

	var result []knowledge.CWEEntry

	for _, weaknessData := range weaknessMap {
		cweEntry := knowledge.CWEEntry{}

		// Basic data
		cweEntry.CWEId = weaknessData.ID
		cweEntry.Name = weaknessData.Name
		cweEntry.Abstraction = weaknessData.Abstraction
		cweEntry.Structure = weaknessData.Structure
		cweEntry.Status = weaknessData.Status
		cweEntry.Description = weaknessData.Description
		cweEntry.LikelihoodOfExploit = weaknessData.LikelihoodOfExploit

		// Extended Description
		cweEntry.ExtendedDescription = ""
		if strings.TrimSpace(strings.ReplaceAll(weaknessData.ExtendedDescription.Text, "\n", "")) != "" {
			cweEntry.ExtendedDescription = cleanString(weaknessData.ExtendedDescription.Text)
		}
		if len(weaknessData.ExtendedDescription.P) > 0 {
			cweEntry.ExtendedDescription += cleanString(strings.Join(weaknessData.ExtendedDescription.P, " "))
		}
		if len(weaknessData.ExtendedDescription.Ul) > 0 {
			for _, ul := range weaknessData.ExtendedDescription.Ul {
				for _, li := range ul.Li {
					cweEntry.ExtendedDescription += fmt.Sprintf(" - %s", cleanString(li.Text))
				}
			}
		}

		// Category Membership
		cweEntry.Categories = []knowledge.CategorySimplified{}
		for _, categoryId := range weaknessData.MemberShips {

			catSimple := knowledge.CategorySimplified{
				ID: categoryId,
			}

			if category, ok := categoryMap[categoryId]; ok {
				catSimple.Name = category.Name
			}

			cweEntry.Categories = append(cweEntry.Categories, catSimple)

		}

		// Parsing of RelatedWeaknesses
		cweEntry.RelatedWeaknesses = []knowledge.RelatedWeakness{}
		for _, relatedWeakness := range weaknessData.RelatedWeaknesses.RelatedWeakness {
			cweEntry.RelatedWeaknesses = append(cweEntry.RelatedWeaknesses, knowledge.RelatedWeakness{
				Nature:  relatedWeakness.Nature,
				CWEID:   relatedWeakness.CWEID,
				ViewID:  relatedWeakness.ViewID,
				Ordinal: relatedWeakness.Ordinal,
				ChainID: relatedWeakness.ChainID,
			})
		}

		// Parsing of ApplicablePlatforms
		cweEntry.ApplicablePlatforms = knowledge.ApplicablePlatform{}
		cweEntry.ApplicablePlatforms.Language = []knowledge.ApplicablePlatformEntry{}
		cweEntry.ApplicablePlatforms.Technology = []knowledge.ApplicablePlatformEntry{}
		cweEntry.ApplicablePlatforms.OperatingSystem = []knowledge.ApplicablePlatformEntry{}
		cweEntry.ApplicablePlatforms.Architecture = []knowledge.ApplicablePlatformEntry{}
		for _, language := range weaknessData.ApplicablePlatforms.Language {
			cweEntry.ApplicablePlatforms.Language = append(cweEntry.ApplicablePlatforms.Language, knowledge.ApplicablePlatformEntry{
				Class:      language.Class,
				Prevalence: language.Prevalence,
				Name:       language.Name,
			})
		}
		for _, os := range weaknessData.ApplicablePlatforms.OperatingSystem {
			cweEntry.ApplicablePlatforms.OperatingSystem = append(cweEntry.ApplicablePlatforms.OperatingSystem, knowledge.ApplicablePlatformEntry{
				Class:      os.Class,
				Prevalence: os.Prevalence,
				Name:       os.Name,
			})
		}
		for _, technology := range weaknessData.ApplicablePlatforms.Technology {
			cweEntry.ApplicablePlatforms.Technology = append(cweEntry.ApplicablePlatforms.Technology, knowledge.ApplicablePlatformEntry{
				Class:      technology.Class,
				Prevalence: technology.Prevalence,
				Name:       technology.Name,
			})
		}
		for _, arch := range weaknessData.ApplicablePlatforms.Architecture {
			cweEntry.ApplicablePlatforms.Architecture = append(cweEntry.ApplicablePlatforms.Architecture, knowledge.ApplicablePlatformEntry{
				Class:      arch.Class,
				Prevalence: arch.Prevalence,
				Name:       arch.Name,
			})
		}

		// Parsing of CommonConsequences
		cweEntry.CommonConsequences = []knowledge.CommonConsequence{}
		for _, consequence := range weaknessData.CommonConsequences.Consequence {
			cweEntry.CommonConsequences = append(cweEntry.CommonConsequences, knowledge.CommonConsequence{
				Scope:      consequence.Scope,
				Note:       consequence.Note,
				Impact:     consequence.Impact,
				Likelihood: consequence.Likelihood,
			})
		}

		// Parsing of ModesOfIntroduction
		cweEntry.ModesOfIntroduction = []knowledge.ModesOfIntroduction{}
		for _, modeOfIntroduction := range weaknessData.ModesOfIntroduction.Introduction {
			parsedModeOfIntroduction := knowledge.ModesOfIntroduction{
				Phase: modeOfIntroduction.Phase,
				Note:  "",
			}
			if strings.TrimSpace(strings.ReplaceAll(modeOfIntroduction.Note.Text, "\n", "")) != "" {
				parsedModeOfIntroduction.Note = cleanString(modeOfIntroduction.Note.Text)
			}
			if len(modeOfIntroduction.Note.P) > 0 {
				parsedModeOfIntroduction.Note += cleanString(strings.Join(modeOfIntroduction.Note.P, " "))
			}
			if len(modeOfIntroduction.Note.Ul) > 0 {
				for _, ul := range modeOfIntroduction.Note.Ul {
					for _, li := range ul.Li {
						parsedModeOfIntroduction.Note += fmt.Sprintf(" - %s", cleanString(li))
					}
				}
			}
			cweEntry.ModesOfIntroduction = append(cweEntry.ModesOfIntroduction, parsedModeOfIntroduction)
		}

		// Parsing of DetectionMethods
		cweEntry.DetectionMethods = []knowledge.DetectionMethod{}
		for _, detectionMethod := range weaknessData.DetectionMethods.DetectionMethod {
			parsedDetectionMethod := knowledge.DetectionMethod{
				Method:      detectionMethod.Method,
				Description: "",
			}
			if strings.TrimSpace(strings.ReplaceAll(detectionMethod.Description.Text, "\n", "")) != "" {
				parsedDetectionMethod.Description = cleanString(detectionMethod.Description.Text)
			}
			if len(detectionMethod.Description.P) > 0 {
				parsedDetectionMethod.Description += cleanString(strings.Join(detectionMethod.Description.P, " "))
			}
			if len(detectionMethod.Description.Ul) > 0 {
				for _, ul := range detectionMethod.Description.Ul {
					for _, li := range ul.Li {
						parsedDetectionMethod.Description += fmt.Sprintf(" - %s", cleanString(li))
					}
				}
			}
			cweEntry.DetectionMethods = append(cweEntry.DetectionMethods, parsedDetectionMethod)
		}

		// Parsing of PotentialMitigations
		cweEntry.PotentialMitigations = []knowledge.PotentialMitigation{}
		for _, mitigation := range weaknessData.PotentialMitigations.Mitigation {
			parsedMitigation := knowledge.PotentialMitigation{
				Phases:      mitigation.Phase,
				Description: "",
			}
			if strings.TrimSpace(strings.ReplaceAll(mitigation.Description.Text, "\n", "")) != "" {
				parsedMitigation.Description = cleanString(mitigation.Description.Text)
			}
			if len(mitigation.Description.P) > 0 {
				parsedMitigation.Description += cleanString(strings.Join(mitigation.Description.P, " "))
			}
			if len(mitigation.Description.Ul) > 0 {
				for _, ul := range mitigation.Description.Ul {
					for _, li := range ul.Li {
						parsedMitigation.Description += fmt.Sprintf(" - %s", cleanString(li))
					}
				}
			}
			cweEntry.PotentialMitigations = append(cweEntry.PotentialMitigations, parsedMitigation)
		}

		// Parsing of ObservedExamples
		cweEntry.ObservedExamples = []knowledge.ObservedExamples{}
		for _, observedExample := range weaknessData.ObservedExamples.ObservedExample {
			parsedExample := knowledge.ObservedExamples{
				Reference:   observedExample.Reference,
				Description: observedExample.Description,
				Link:        observedExample.Link,
			}
			cweEntry.ObservedExamples = append(cweEntry.ObservedExamples, parsedExample)
		}

		// Parsing of AlternateTerms
		cweEntry.AlternateTerms = []knowledge.AlternateTerm{}
		for _, alternateTerm := range weaknessData.AlternateTerms.AlternateTerm {
			parsedAlternateTerm := knowledge.AlternateTerm{
				Term:        alternateTerm.Term,
				Description: "",
			}
			if strings.TrimSpace(strings.ReplaceAll(alternateTerm.Description.Text, "\n", "")) != "" {
				parsedAlternateTerm.Description = cleanString(alternateTerm.Description.Text)
			}
			if len(alternateTerm.Description.P) > 0 {
				parsedAlternateTerm.Description += cleanString(strings.Join(alternateTerm.Description.P, " "))
			}
			if len(alternateTerm.Description.Ul) > 0 {
				for _, ul := range alternateTerm.Description.Ul {
					for _, li := range ul.Li {
						parsedAlternateTerm.Description += fmt.Sprintf(" - %s", cleanString(li))
					}
				}
			}
			cweEntry.AlternateTerms = append(cweEntry.AlternateTerms, parsedAlternateTerm)
		}

		// Parsing of TaxonomyMappings
		cweEntry.TaxonomyMappings = []knowledge.TaxonomyMapping{}
		for _, taxonomyMapping := range weaknessData.TaxonomyMappings.TaxonomyMapping {
			parsedTaxonomyMapping := knowledge.TaxonomyMapping{
				TaxonomyName: taxonomyMapping.TaxonomyName,
				EntryID:      taxonomyMapping.EntryID,
				EntryName:    taxonomyMapping.EntryName,
				MappingFit:   taxonomyMapping.MappingFit,
			}
			cweEntry.TaxonomyMappings = append(cweEntry.TaxonomyMappings, parsedTaxonomyMapping)
		}

		// Parsing of AffectedResources
		cweEntry.AffectedResources = append(cweEntry.AffectedResources, weaknessData.AffectedResources.AffectedResource...)

		// Parsing of FunctionalAreas
		cweEntry.FunctionalAreas = append(cweEntry.FunctionalAreas, weaknessData.FunctionalAreas.FunctionalArea...)

		result = append(result, cweEntry)
	}

	return result, nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
