# CORRECTED Trust Form — Step-by-Step Instructions

## What Was Wrong

Your current payload looks like this:
```json
{
  "responses": [
    {"questionId": "...", "values": ["N/A"]}
  ]
}
```

The API actually expects THIS:
```json
[
  {
    "questionId": "...",
    "sectionId": "...",
    "responses": [
      {"response": "N/A"}
    ]
  }
]
```

Three problems:
1. **Root must be an array `[...]`**, not an object `{...}`
2. **Each question is its own object** with `questionId`, `sectionId`, and `responses`
3. **Answer field is `"response"`** (singular string), not `"values"` (array)

---

## What You Need To Do

You do NOT need any new variables, GET steps, or Parse JSON steps.
Just replace the Body of each Submit_Trust_Section action.

### For each section:

1. Click on the **Submit_Trust_Section_N** action
2. Click in the **Body** field
3. **Delete everything** in the Body
4. Switch to the **Expression** tab
5. Paste the expression below (for that section)
6. Click **OK**

> IMPORTANT: Do NOT type `@` at the start. The Expression tab adds it automatically.

---

## Section 1 — Expression

```
json(concat('[{"questionId":"ebd86e1d-810a-4400-bd2c-e1d9ed462eec","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"',coalesce(triggerBody()?['ApplicationService'],'N/A'),'"}]},{"questionId":"3f1266c0-c7c0-49fe-a364-b0fe8ffedafc","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"',outputs('Translate_Trust_S1Q3_Processing_Activity'),'"}]},{"questionId":"e5271835-3e89-42b4-b4f5-17346a31c6c4","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"',coalesce(triggerBody()?['ServiceDescription'],'N/A'),'"}]},{"questionId":"38158f80-c4de-443e-bc6c-64ac5bfe0bd7","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"',outputs('Translate_Trust_S1Q5_Purpose_for_Processing'),'"}]}]'))
```

What this produces at runtime:
```json
[
  {"questionId":"ebd86e1d-810a-4400-bd2c-e1d9ed462eec","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"N/A"}]},
  {"questionId":"3f1266c0-c7c0-49fe-a364-b0fe8ffedafc","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"2e4cc071-5e44-4ee8-9f44-153fc7f86b7a"}]},
  {"questionId":"e5271835-3e89-42b4-b4f5-17346a31c6c4","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"N/A"}]},
  {"questionId":"38158f80-c4de-443e-bc6c-64ac5bfe0bd7","sectionId":"f007cd7d-61c0-4d29-958e-0e85317eee22","responses":[{"response":"f5b6915b-ba8e-4701-a9f7-9d6298eb4391"}]}
]
```

---

## Section 2 — Expression

```
json(concat('[{"questionId":"54609d93-27f3-47b9-9405-1fadd6d9f2bb","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q2_Additional_Data_Elements'),'"}]},{"questionId":"11a1335f-78df-4e8d-9d38-3566f383fb24","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q4_Data_Subject_Region'),'"}]},{"questionId":"edc80ecb-35b5-46b6-abb5-3631aefa51a0","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',coalesce(triggerBody()?['Common_Subprocessors'],'N/A'),'"}]},{"questionId":"5b6ca434-d65d-43ec-941f-fb6ba2fe2e89","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q6_Hosting_Arrangement'),'"}]},{"questionId":"4f3e7302-e511-4875-a755-3371bbb9001e","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q7_Hosting_Provider'),'"}]},{"questionId":"c2ccef7c-e055-4148-add7-5d9d1cb6f1a8","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q8_Instance_Location'),'"}]},{"questionId":"2221e756-6f3f-4da4-9d82-0e45f3a50782","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q9_Third_Party_or_Service_Provider'),'"}]},{"questionId":"967cc49f-ef1c-4daf-98de-dbbb07ffe7c8","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q10_Sharing_of_Data'),'"}]},{"questionId":"816ca963-6cfd-4d57-bb7c-1447bb5b6452","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q11_Selling_of_Data'),'"}]},{"questionId":"8fea67aa-736f-46e9-b81f-903e678686da","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q12_GLBA'),'"}]},{"questionId":"47d3c0be-edb1-46f3-8dcc-8546b6370fa4","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q13_Web_Mobile_Based'),'"}]},{"questionId":"fba3cd7a-6dd9-418f-a5ba-5ae02e5344c2","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q14_User_Interface'),'"}]},{"questionId":"35d06d92-6893-4403-8326-da8d8f4b06d6","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q15_WCAG_Compliance'),'"}]},{"questionId":"3919a107-bd86-4107-8aa1-9c17547f011b","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q16_Uses_Cookies'),'"}]},{"questionId":"5d5f5271-5c5f-498a-af85-8ff6e5ff11d9","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q17_OneTrust_Integration'),'"}]},{"questionId":"3a455264-fe30-4cfc-ab2f-0204bf0efcde","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q18_Google_Analytics'),'"}]},{"questionId":"9a40e9cd-7037-4161-8ef3-359abce8c575","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q19_Children_Under_16'),'"}]},{"questionId":"aed7a4fd-da58-45db-9cda-40a7d0380ac4","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q20_Automated_Decision_Making'),'"}]},{"questionId":"01269fe4-b394-4d85-abe4-56398ae5dc7f","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q21_AI_Tools'),'"}]},{"questionId":"1928e07f-f73a-4c9a-8afb-6d7f619b8b06","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',coalesce(triggerBody()?['AIRA_AIDescription'],'N/A'),'"}]},{"questionId":"75a1cd09-6005-4571-9b91-2d3761b200a1","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q23_Privacy_Notice'),'"}]},{"questionId":"a8570434-8e7f-45ed-a5a9-f9a720a2b852","sectionId":"09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d","responses":[{"response":"',outputs('Translate_Trust_S2Q24_Privacy_Due_Diligence'),'"}]}]'))
```

---

## Section 3 — Expression

```
json(concat('[{"questionId":"38b862a5-2cb4-4310-bb30-09e80eb6ae34","sectionId":"7196fa0e-e0a8-4565-95b5-7358d0b2d4f1","responses":[{"response":"',coalesce(triggerBody()?['VRP_SystemsCollect'],''),'"}]},{"questionId":"ff3b21b7-0f8e-4747-8b3b-fbf81db48f76","sectionId":"7196fa0e-e0a8-4565-95b5-7358d0b2d4f1","responses":[{"response":"',coalesce(triggerBody()?['VRP_SystemsProcess'],''),'"}]},{"questionId":"df26c544-b4a9-4028-b5d3-7339a1591331","sectionId":"7196fa0e-e0a8-4565-95b5-7358d0b2d4f1","responses":[{"response":"',coalesce(triggerBody()?['VRP_SystemsTransfer'],''),'"}]},{"questionId":"98a06c1b-ee40-498c-ae8e-8555e2adbf43","sectionId":"7196fa0e-e0a8-4565-95b5-7358d0b2d4f1","responses":[{"response":"',outputs('Translate_Trust_S3Q4_Transfer_to_Affiliates'),'"}]},{"questionId":"5e59bdc8-c40f-47e4-bf66-15b0724cb394","sectionId":"7196fa0e-e0a8-4565-95b5-7358d0b2d4f1","responses":[{"response":"',outputs('Translate_Trust_S3Q5_Data_Shared_Outside_Country'),'"}]},{"questionId":"9c605029-b56a-4f84-8db9-ef5d095d18c3","sectionId":"7196fa0e-e0a8-4565-95b5-7358d0b2d4f1","responses":[{"response":"',coalesce(triggerBody()?['Common_DataTransferRegions'],''),'"}]}]'))
```

---

## Section 4 — Expression

```
json(concat('[{"questionId":"3a4608c7-2785-41e0-9ddd-23ece9ddea13","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q1_Applicable_Laws'),'"}]},{"questionId":"403f3d9e-6d85-43e3-bb86-8d9557974848","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q2_Legal_Basis'),'"}]},{"questionId":"bfbebb79-f95c-4279-9679-3a77fbfeec9d","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q3_Risk_Impact_to_Rights'),'"}]},{"questionId":"ec8bbe36-f742-4ac8-b846-27cf3aa41434","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q4_Legitimate_Interests_Outweighed'),'"}]},{"questionId":"84105b5d-4f4e-404c-9efe-9c9f523b258c","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q5_Data_Operations'),'"}]},{"questionId":"4b749a58-7351-47d8-b81d-d115dac35300","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q6_Consent_Required'),'"}]},{"questionId":"551c4978-525a-49f8-9cc7-cfe0dc6cdb0e","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q7_Consent_Withdrawal_Steps'),'"}]},{"questionId":"ff297869-05d9-4cc5-807d-68bb6ec0bb7d","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q8_Parental_Consent'),'"}]},{"questionId":"c1dab02b-2648-49b0-ae12-0d8eaa087458","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q9_CA_Under_16_Consent'),'"}]},{"questionId":"6a88c2a7-eac2-42a7-bb25-429c6b42c829","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',coalesce(triggerBody()?['Common_NoticeToDataSubject'],''),'"}]},{"questionId":"1074c38c-9cb3-42dd-98bd-296d6ac75f83","sectionId":"6196e500-c3fd-4c7b-992c-891ff9ff1a64","responses":[{"response":"',outputs('Translate_Trust_S4Q11_Surveillance'),'"}]}]'))
```

---

## Section 5 — Expression

```
json(concat('[{"questionId":"1874fdf8-b276-4215-915f-3250463a8557","sectionId":"c7d2cba1-2238-4e58-9a89-2b2287394599","responses":[{"response":"',outputs('Translate_Trust_S5Q1_Privacy_Contract_Required'),'"}]},{"questionId":"d2090348-7dd2-4874-9675-46ab20270189","sectionId":"c7d2cba1-2238-4e58-9a89-2b2287394599","responses":[{"response":"',outputs('Translate_Trust_S5Q2_Privacy_Contract_Doc_Type'),'"}]}]'))
```

---

## Section 6 — Expression

```
json(concat('[{"questionId":"f035f24f-9b60-483f-a8b3-49212b372db9","sectionId":"2da53f65-9c4d-4411-b139-b95ddc380b6e","responses":[{"response":"',coalesce(triggerBody()?['AdditionalContext'],''),'"}]}]'))
```

---

## Flow Order (same as before — no new steps needed)

```
Create_PIA_Assessment
  → Set PIAAssessmentId
    → Delay (3 sec)
      → Submit_Trust_Section_1  (body changed)
        → Submit_Trust_Section_2  (body changed)
          → Submit_Trust_Section_3  (body changed)
            → Submit_Trust_Section_4  (body changed)
              → Submit_Trust_Section_5  (body changed)
                → Submit_Trust_Section_6  (body changed)
```

No GET step. No new variables. No Parse JSON.
Just replace each section's body expression.

---

## Quick Reference: What Changed

| Old (Wrong) | New (Correct) |
|-------------|---------------|
| `{"responses": [...]}` | `[{...}, {...}]` |
| Root is an object | Root is an array |
| `"values": ["N/A"]` | `"responses": [{"response": "N/A"}]` |
| No sectionId | `"sectionId": "..."` on every question |
| Questions grouped flat | Each question is its own object |

---

## Section ID Reference

| Section | sectionId |
|---------|-----------|
| 1 - Initial Intake Form | `f007cd7d-61c0-4d29-958e-0e85317eee22` |
| 2 - Privacy Impact Assessment | `09e9eae3-6c60-4b49-8d48-e0b0e6bfde5d` |
| 3 - Transfer Impact Assessment | `7196fa0e-e0a8-4565-95b5-7358d0b2d4f1` |
| 4 - Legal Basis & Compliance | `6196e500-c3fd-4c7b-992c-891ff9ff1a64` |
| 5 - Privacy Contractual Language | `c7d2cba1-2238-4e58-9a89-2b2287394599` |
| 6 - Additional Information | `2da53f65-9c4d-4411-b139-b95ddc380b6e` |

---

## If It Still Fails

If you still get 400 after this change, the remaining possibilities are:
1. **Assessment is COMPLETED** — check status of the assessment you're submitting to
2. **MULTICHOICE needs option TEXT not UUID** — try "Business Operations" instead of the UUID
3. **sectionIds differ per assessment instance** — you may need to request GET assessment permission from your OneTrust admin to retrieve them dynamically

## Regarding Your PIA Flow

Your working PIA flow uses `{"responses": [{"questionId": "...", "values": ["..."]}]}` — which is technically the wrong format too. It may be working because:
- The PIA template is more lenient / has a single section
- OneTrust accepts a legacy format for simpler templates
- It's actually silently failing but you haven't noticed

After fixing the Trust form, consider updating the PIA sections to this correct format too.
