# OneTrust Trust Form 400 Error — Root Cause Analysis & Fix

## Problem Summary
POST to `/api/assessment/v2/assessments/{assessmentId}/responses` returns 400 "Request could not be parsed" for Trust Form submissions, while the identical pattern works for PIA Form submissions in the same Power Automate flow.

---

## Root Cause Analysis (Ranked by Likelihood)

### #1 — MOST LIKELY: `sectionId` Required in Request Body

**Evidence:**
- The OneTrust Create Assessment Risk API (a sibling endpoint at the same API level) **requires `sectionId` as a mandatory field**
- Multiple search results infer the Submit Responses body includes `sectionId` alongside `questionId`
- The OneTrust Developer Portal workflow documentation states: "Use Get Assessment to obtain `sectionId` and `questionId` values needed for submitting responses"
- The error "Request could not be parsed" is a **deserialization error**, meaning the API can't map the incoming JSON to its expected schema — this happens when required top-level fields are missing
- The PIA template may have a simpler structure (single section or auto-inferred section), while the Trust Form has **6 explicit sections** that the API can't auto-resolve

**The Fix — Add `sectionId` to the request body:**
```json
{
  "sectionId": "f007cd7d-61c0-4d29-958e-0e85317eee22",
  "responses": [
    {
      "questionId": "ebd86e1d-810a-4400-bd2c-e1d9ed462eec",
      "values": ["N/A"]
    },
    {
      "questionId": "3f1266c0-c7c0-49fe-a364-b0fe8ffedafc",
      "values": ["2e4cc071-5e44-4ee8-9f44-153fc7f86b7a"]
    },
    {
      "questionId": "e5271835-3e89-42b4-b4f5-17346a31c6c4",
      "values": ["N/A"]
    },
    {
      "questionId": "38158f80-c4de-443e-bc6c-64ac5bfe0bd7",
      "values": ["f5b6915b-ba8e-4701-a9f7-9d6298eb4391"]
    }
  ]
}
```

**Section IDs for each Trust Form section:**
| Section | Name | sectionId |
|---------|------|-----------|
| 1 | Initial Intake Form - Privacy Assessment | `f007cd7d-61c0-4d29-958e-0e85317eee22` |
| 2 | Privacy Impact Assessment | `09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d` |
| 3 | Transfer Impact Assessment | `7196fa0e-e0a8-4565-95b5-7358d0b2d4f1` |
| 4 | Legal Basis & Compliance Requirements | `6196e500-c3fd-4c7b-992c-891ff9ff1a64` |
| 5 | Privacy Contractual Language | `c7d2cba1-2238-4e58-9a89-2b2287394599` |
| 6 | Additional Information | `2da53f65-9c4d-4411-b139-b95ddc380b6e` |

> **IMPORTANT NOTE:** These sectionIds were captured from a specific completed assessment. Section IDs may vary per assessment instance (generated at launch time) vs being fixed per template. You should GET the newly created assessment first to capture the actual sectionIds for that instance.

---

### #2 — Assessment Status Blocking Submissions

**Evidence:**
- OneTrust documentation explicitly states: **"Responses cannot be added to assessments that have already been completed."**
- The Trust Form GET structure was captured from a **COMPLETED** assessment
- The PIA assessment was confirmed **NOT_STARTED** when submissions worked
- The test assessment `ca24ab79-582b-4235-9178-86078f9553a0` may have been tested against a completed assessment

**How to verify:**
```
GET https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/ca24ab79-582b-4235-9178-86078f9553a0
```
Check the `"status"` field. If it's `"COMPLETED"`, that's your answer.

**How to rule out (in the flow):**
If the assessment is created by `Create_PIA_Assessment` in the same flow run, it should be `NOT_STARTED`. But verify the flow run history — check the response body of `Create_PIA_Assessment` and the value stored in `PIAAssessmentId`. Make sure it's a clean UUID string (not a JSON object or quoted string).

---

### #3 — `PIAAssessmentId` Variable Contains Full JSON Object, Not Just UUID

**Evidence:**
Looking at the flow code:
```json
"Set_variable_1": {
  "type": "SetVariable",
  "inputs": {
    "name": "PIAAssessmentId",
    "value": "@body('Create_PIA_Assessment')"
  }
}
```

The variable is set to `@body('Create_PIA_Assessment')` — this is the **entire response body**, not just the assessment ID. The Create Assessment API likely returns a JSON object like:
```json
{
  "assessmentId": "ca24ab79-582b-4235-9178-86078f9553a0",
  "name": "...",
  "status": "NOT_STARTED"
}
```

If `PIAAssessmentId` contains the full JSON object, then:
```
@concat('...assessments/', variables('PIAAssessmentId'), '/responses')
```
would produce a malformed URL like:
```
.../assessments/{"assessmentId":"ca24ab79-...","name":"..."}/responses
```

**However**, the failing request log shows a clean URL with just the UUID, so Power Automate may be auto-coercing. But this is still worth investigating — make sure `PIAAssessmentId` is set to just the ID string:
```
@body('Create_PIA_Assessment')?['assessmentId']
```
or check what the Create Assessment API actually returns (it might return just a plain string ID).

---

### #4 — Question Type Format Mismatch

**Evidence:**
- The GET response shows MULTICHOICE answers stored as **option TEXT** (e.g., "Business Operations"), not option UUID
- Your submit sends option **UUIDs** for MULTICHOICE
- The PIA form also sends option UUIDs and that works
- This makes UUID format likely valid, but it's possible different templates handle options differently

**Test:** Try sending option TEXT instead of UUID for one MULTICHOICE question:
```json
{
  "questionId": "3f1266c0-c7c0-49fe-a364-b0fe8ffedafc",
  "values": ["Collect"]
}
```
instead of:
```json
{
  "questionId": "3f1266c0-c7c0-49fe-a364-b0fe8ffedafc",
  "values": ["2e4cc071-5e44-4ee8-9f44-153fc7f86b7a"]
}
```

---

### #5 — Different API Schema Version or Endpoint Path

**Evidence:**
- OneTrust docs reference multiple URL patterns:
  - `/api/assessment/v2/assessments/{id}/responses`
  - `/api/assessment-v2/v2/assessments/{id}/responses`
  - `/api/assessment/v2/assessments/{id}/submit/responses`
- If the endpoint path is slightly wrong, the server might return a generic 400

**Test:** Try the alternative path:
```
POST https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/{id}/submit/responses
```

---

## Recommended Testing Order

### Step 1: Quick Isolation Test (Postman/curl)
Remove Power Automate from the equation entirely. Use curl or Postman to POST a single hardcoded response to a **freshly created** Trust Form assessment:

```bash
# First, create a fresh assessment
curl -X POST "https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "templateId": "24351828-06a6-43b7-996d-6a06c9ad60d4",
    "name": "API Test - Trust Form",
    "orgGroupId": "b7890996-1217-422b-9927-bd03196d525c",
    "respondents": [{"respondentId": "9399dae7-f30a-41b1-9080-23ee824b219b", "respondentName": "OneTrust User"}]
  }'

# Save the returned assessmentId, then GET the assessment to find sectionIds
curl -X GET "https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/NEW_ASSESSMENT_ID" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Then try submitting WITH sectionId
curl -X POST "https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/NEW_ASSESSMENT_ID/responses" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sectionId": "SECTION_1_ID_FROM_GET",
    "responses": [
      {
        "questionId": "ebd86e1d-810a-4400-bd2c-e1d9ed462eec",
        "values": ["Test Value"]
      }
    ]
  }'
```

### Step 2: If sectionId doesn't work, try WITHOUT sectionId on a fresh assessment
```bash
curl -X POST "https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/NEW_ASSESSMENT_ID/responses" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "responses": [
      {
        "questionId": "ebd86e1d-810a-4400-bd2c-e1d9ed462eec",
        "values": ["Test Value"]
      }
    ]
  }'
```

If Step 2 succeeds, the issue was assessment status (not sectionId).
If Step 1 succeeds but Step 2 fails, sectionId is required.

### Step 3: If both fail, try the alternative endpoint path
```
POST .../assessments/{id}/submit/responses
```

### Step 4: If still failing, try option TEXT instead of UUID for MULTICHOICE

---

## Power Automate Fix (Once Root Cause Confirmed)

### If sectionId is required — Updated Section 1 body:

**Using native JSON:**
```json
{
  "sectionId": "@{variables('TrustSection1Id')}",
  "responses": [
    {
      "questionId": "ebd86e1d-810a-4400-bd2c-e1d9ed462eec",
      "values": ["@{coalesce(triggerBody()?['ApplicationService'],'N/A')}"]
    },
    {
      "questionId": "3f1266c0-c7c0-49fe-a364-b0fe8ffedafc",
      "values": ["@{outputs('Translate_Trust_S1Q3_Processing_Activity')}"]
    },
    {
      "questionId": "e5271835-3e89-42b4-b4f5-17346a31c6c4",
      "values": ["@{coalesce(triggerBody()?['ServiceDescription'],'N/A')}"]
    },
    {
      "questionId": "38158f80-c4de-443e-bc6c-64ac5bfe0bd7",
      "values": ["@{outputs('Translate_Trust_S1Q5_Purpose_for_Processing')}"]
    }
  ]
}
```

**Using @json(concat(...)) pattern (more reliable):**
```
@json(concat(
  '{"sectionId":"', variables('TrustSection1Id'), '",',
  '"responses":[',
    '{"questionId":"ebd86e1d-810a-4400-bd2c-e1d9ed462eec","values":["', coalesce(triggerBody()?['ApplicationService'],'N/A'), '"]},',
    '{"questionId":"3f1266c0-c7c0-49fe-a364-b0fe8ffedafc","values":["', outputs('Translate_Trust_S1Q3_Processing_Activity'), '"]},',
    '{"questionId":"e5271835-3e89-42b4-b4f5-17346a31c6c4","values":["', coalesce(triggerBody()?['ServiceDescription'],'N/A'), '"]},',
    '{"questionId":"38158f80-c4de-443e-bc6c-64ac5bfe0bd7","values":["', outputs('Translate_Trust_S1Q5_Purpose_for_Processing'), '"]}',
  ']}'
))
```

### Additional Flow Changes Needed:

1. **Add a GET Assessment step** after Create to capture section IDs dynamically:
   ```
   GET https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/{PIAAssessmentId}
   ```

2. **Parse the GET response** to extract sectionIds from `sectionHeaders[].sectionId`

3. **Set variables** for each section ID (or use expressions to reference them directly)

4. **Fix PIAAssessmentId** — ensure it's set to just the ID string, not the full response body:
   ```
   @body('Create_PIA_Assessment')?['assessmentId']
   ```
   (or whatever field name the Create Assessment response uses for the ID)

---

## Why PIA Works But Trust Doesn't

The most likely explanation: **The PIA template has a simpler section structure** (possibly a single section, or sections that don't require explicit `sectionId` in the submit payload). The Trust Form template has 6 complex sections, and the API requires `sectionId` to know which section the responses belong to.

Alternatively: If the PIA assessment uses a different template that has its own section mapping rules, or if PIA questions have globally unique IDs that the API can resolve without section context, while Trust Form questions need section disambiguation.
