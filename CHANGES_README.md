# Changes Made to Trust Form Scope

## Summary of Changes

### Change 1: Added `sectionId` to ALL 6 section submissions
**Why:** The OneTrust API requires `sectionId` when a template has multiple sections. The Trust Form has 6 sections — without `sectionId`, the API can't determine which section the responses belong to, causing `400 "Request could not be parsed"`.

Each `Submit_Trust_Section_N` body now includes:
```json
{"sectionId": "<dynamic from GET>", "responses": [...]}
```

### Change 2: Added `GET_Assessment_Structure` step
**Why:** Dynamically retrieves the assessment structure after creation to capture the actual `sectionId` values for the new assessment instance. This is more robust than hardcoding IDs.

**Endpoint:** `GET /api/assessment/v2/assessments/{assessmentId}`

### Change 3: Added `Parse_Assessment_SectionHeaders` step
**Why:** Parses the `sectionHeaders` array from the GET response so we can extract each section's `sectionId` by index.

### Change 4: Added 6 `Set_TrustSectionNId` variable steps
**Why:** Stores each section ID in a named variable for clean reference in the submit actions.

**New variables you need to create in Power Automate:**
- `TrustSection1Id` (string)
- `TrustSection2Id` (string)
- `TrustSection3Id` (string)
- `TrustSection4Id` (string)
- `TrustSection5Id` (string)
- `TrustSection6Id` (string)

### Change 5: Converted Sections 1 & 2 to `@json(concat(...))` pattern
**Why:** Sections 1 and 2 previously used native JSON body with `@{expression}` interpolation. Switched to `@json(concat(...))` pattern (same as sections 3-6 and the working PIA sections) for consistency and to eliminate any potential double-serialization risk.

### Change 6: Added `_NOTE_-_PIAAssessmentId_Fix` compose step
**Why:** Flags a potential issue — `Set_variable_1` sets `PIAAssessmentId` to `@body('Create_PIA_Assessment')`. If the Create API returns a JSON object (not a bare string), you need to change this to `@body('Create_PIA_Assessment')?['assessmentId']`. Check your run history to verify.

---

## New Execution Order

```
Create_PIA_Assessment
  → Set_variable_-_PIAAssessmentId
    → _NOTE_-_PIAAssessmentId_Fix (Compose, no-op — just a note)
      → Delay (3 sec)
        → GET_Assessment_Structure
          → Parse_Assessment_SectionHeaders
            → Set_TrustSection1Id
              → Set_TrustSection2Id
                → Set_TrustSection3Id
                  → Set_TrustSection4Id
                    → Set_TrustSection5Id
                      → Set_TrustSection6Id
                        → Submit_Trust_Section_1
                          → Submit_Trust_Section_2
                            → Submit_Trust_Section_3
                              → Submit_Trust_Section_4
                                → Submit_Trust_Section_5
                                  → Submit_Trust_Section_6
```

---

## Expected Section ID Mapping (for reference)

These are the sectionIds from the known Trust Form template. The dynamic GET step should return these same values for any assessment created from template `24351828-06a6-43b7-996d-6a06c9ad60d4`:

| Index | Section Name | Expected sectionId |
|-------|-------------|-------------------|
| 0 | Initial Intake Form - Privacy Assessment | `f007cd7d-61c0-4d29-958e-0e85317eee22` |
| 1 | Privacy Impact Assessment | `09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d` |
| 2 | Transfer Impact Assessment | `7196fa0e-e0a8-4565-95b5-7358d0b2d4f1` |
| 3 | Legal Basis & Compliance Requirements | `6196e500-c3fd-4c7b-992c-891ff9ff1a64` |
| 4 | Privacy Contractual Language | `c7d2cba1-2238-4e58-9a89-2b2287394599` |
| 5 | Additional Information | `2da53f65-9c4d-4411-b139-b95ddc380b6e` |

> **Note:** If the `sectionHeaders` array includes a Welcome section (index 0), all indices shift by 1. Check the GET response to verify the order.

---

## Quick-Test Alternative (Hardcoded sectionIds)

If you want to test the `sectionId` hypothesis immediately without the GET/Parse/Set steps, you can temporarily hardcode the sectionIds directly in each submit body:

```
@json(concat(
  '{"sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[',
  ...
  ']}'
))
```

This bypasses the GET step and is useful for a quick validation. If it works, you know `sectionId` was the issue and can decide whether to keep hardcoded IDs or use the dynamic approach.

---

## If `sectionId` Doesn't Fix It

If adding `sectionId` still returns 400, try these in order:

1. **Check assessment status** — GET the assessment and verify `"status": "NOT_STARTED"`
2. **Try endpoint variant** — Change `/responses` to `/submit/responses` in the URL
3. **Try option TEXT for MULTICHOICE** — Send `"Business Operations"` instead of UUID
4. **Try HTML-wrapped TEXTBOX values** — Send `"<p>N/A</p>"` instead of `"N/A"`
5. **Include the INVENTORY question (Q1 Section 1)** — It may be required even if you skip it
