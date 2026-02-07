# AIRA — Corrected Section Expressions

Format: Each section is a `json(concat(...))` expression for the **Body** field of the corresponding `Submit_AIRA_Section_N` HTTP POST action.

**API Endpoint per section:**
```
POST https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/{AIRAAssessmentId}/sections/{sectionId}/questions/responses
```

**Key rules:**
- Root is an **array** `[...]`
- Each question gets `questionId`, `sectionId`, and `responses` array
- MULTICHOICE/YESNO answers use `"responseId": "uuid"` (NOT plain text)
- TEXTBOX answers use `"response": "text"`
- PERSONAL_DATA questions are skipped (handled separately by OneTrust)
- Hidden questions with nav rules (Q3 S1, Q8 S2, Q3 S3, Q3 S7) are included but may be skipped by the API if not triggered

---

## Section 1 — AI General Intake
sectionId: `813e1fa7-755d-4817-a90a-8aaf5b447b54`

Questions:
- Q1 (TEXTBOX): App description — triggerBody `AIRA_Description`
- Q2 (MULTICHOICE multi-select): AI type — triggerBody `AIRA_AIType` (pass option text, needs lookup)
- Q3 (YESNO, hidden): Generative AI — uses `Translate_AIRA_GenerativeAI`
- Q4 (MULTICHOICE multi-select): Data captured — triggerBody `AIRA_DataCaptured`
- Q5 (PERSONAL_DATA): Skipped
- Q6 (MULTICHOICE): Children data — uses `Translate_Common_ChildrenData`
- Q7 (MULTICHOICE multi-select): Country/region — triggerBody `AIRA_DataSubjectRegion` (pass option text)
- Q8 (MULTICHOICE): Open/close source — triggerBody `AIRA_SourceType`

### Expression:

```
json(concat('[{"questionId":"a60eafd3-7262-45e1-84ac-ba20a90d9afe","sectionId":"813e1fa7-755d-4817-a90a-8aaf5b447b54","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_Description'],'N/A'),'"','\"'),'\','\\'),'"}]},{"questionId":"92d36ff7-8870-4c14-8860-0a46ab84e7fc","sectionId":"813e1fa7-755d-4817-a90a-8aaf5b447b54","responses":[{"responseId":"',outputs('Translate_AIRA_GenerativeAI'),'"}]},{"questionId":"a38c5cfe-000d-4ffa-bb19-fdff71169190","sectionId":"813e1fa7-755d-4817-a90a-8aaf5b447b54","responses":[{"responseId":"',outputs('Translate_Common_ChildrenData'),'"}]}]'))
```

**Note on Q2 (AI Type), Q4 (Data Captured), Q7 (Country/Region), Q8 (Open/Close Source):**
These are MULTICHOICE questions where the user selects from a list of named options (not Yes/No). If the flow currently passes these as text, you need **Lookup** Compose actions (like `Lookup_UserType`) to map text values to option UUIDs. Here are the option UUID mappings if you want to add Lookups:

**Q2 — AI Type options:**
| Option | UUID |
|--------|------|
| Computer Vision | `68b8b099-dc14-4e0c-8f59-8ea6ffa0b6a1` |
| Deep Learning | `e504ff38-a736-4478-9232-db18dcbf75b7` |
| Generative AI | `c114cf8f-6e93-415d-add3-09233660c4d7` |
| Natural Language Processing (NLP) | `222ca6fc-10f4-47aa-8bb8-44c2fa0f8da3` |
| Reinforcement Learning | `32f4195b-4973-4f32-94c1-2fd53a9cec60` |
| Robotics | `10b6264f-fe74-4970-9eee-93850775a166` |
| Other | `4c690653-3260-49f5-924d-ce6ceb0053b8` |

**Q4 — Data Captured options:**
| Option | UUID |
|--------|------|
| Personal Identifiable Information | `f1f72021-2e2e-4247-84ce-de1a4d43f292` |
| Sensitive Data | `13961632-ad1b-4935-a669-dc48b058dec7` |
| Business Data | `25233d9d-f709-45ac-a6e0-d5c7be4ec326` |
| Technical Data (Metadata, IP Addresses, Etc) | `c28b78c6-2791-4e7a-8baf-18339e9dfdcc` |
| Other | `30d716ae-6892-4739-934f-954f04c46925` |

**Q6 — Children Data options:**
| Option | UUID |
|--------|------|
| Yes | `4dd6d2c2-d334-43fe-bb3f-c9238f2e29b4` |
| No | `09b9552c-7198-49e6-a5f7-b61d6a99ad16` |
| Not Sure | `ae36f0d1-3676-4e53-b228-67bf01be73ab` |
| N/A | `2d225f11-4589-4d4a-9836-83930cd8e38c` |

**Q8 — Open/Close Source options:**
| Option | UUID |
|--------|------|
| Open source | `60992775-d564-4d6b-99fe-2e2781fe742b` |
| Close source | `8e5fd3db-6931-4966-bc08-210a85e1c63c` |

---

## Section 2 — Human Agency and Oversight
sectionId: `16f5e2d3-7b7b-45fd-a02f-8356a6105fec`

All questions are MULTICHOICE with Yes/No/N/A options. All use existing Translate outputs.

### Expression:

```
json(concat('[{"questionId":"41ca4085-4dc4-42cb-babd-d9b3b9a02608","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_HumanInteraction'),'"}]},{"questionId":"5ed96d77-853c-40cb-a532-30efc703e710","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_EndUserInterference'),'"}]},{"questionId":"8bb0d687-2f67-4305-a0dc-6b078f5d49b1","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_AvoidProcedure'),'"}]},{"questionId":"a1326fd1-b3eb-4f4c-aabf-11132a81e30f","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_SocialSimulation'),'"}]},{"questionId":"346b23b3-7ad3-46f3-9c7c-8acc2a1cafbe","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_HumanAttachmentRisk'),'"}]},{"questionId":"de4aee11-d56a-45cf-8d0a-f6b6824aaada","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_HumanAttachmentMeasures'),'"}]},{"questionId":"afe5d08c-5791-4f7d-a957-77d02ecd1a76","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_AITraining'),'"}]},{"questionId":"24c24687-a0bb-4f8d-bb47-e62d42ef774e","sectionId":"16f5e2d3-7b7b-45fd-a02f-8356a6105fec","responses":[{"responseId":"',outputs('Translate_AIRA_ContinualLearning'),'"}]}]'))
```

**Note:** Q9 (Continual Learning delivery - `66dec816-75d5-4599-933a-7549739c5621`) has options: "Only to deliver services to MVW" / "Both" / "Train the overall model". No Translate exists for this yet. If needed:
| Option | UUID |
|--------|------|
| Only to deliver services to MVW | `a441494e-325a-4ed0-bf01-d92c482e4662` |
| Both | `2cbeb41f-8bcb-4fdf-ab61-6fe5a9f31718` |
| Train the overall model | `df8edf51-011c-4d7b-a5c8-f2421d21ee26` |

---

## Section 3 — Privacy and Data Governance
sectionId: `9c8ee100-db8c-48c4-bda3-6ce76d6abd7c`

- Q1 (TEXTBOX): Privacy impact — triggerBody `AIRA_PrivacyImpact`
- Q2 (MULTICHOICE Y/N/NA): Privacy risks — uses `Translate_AIRA_PrivacyRisks`
- Q3 (TEXTBOX, hidden): Risk mechanism — triggerBody `AIRA_RiskMechanism`
- Q4 (MULTICHOICE multi-select): Data governance trained/developed — needs Lookup
- Q5 (MULTICHOICE multi-select): Data governance measures — needs Lookup
- Q6 (MULTICHOICE Y/N/NA): Data governance consent/object rights — uses `Translate_AIRA_DataGovernance1`

### Expression:

```
json(concat('[{"questionId":"a4931655-fc0c-401c-ade1-5ee6b79d9888","sectionId":"9c8ee100-db8c-48c4-bda3-6ce76d6abd7c","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_PrivacyImpact'],'N/A'),'"','\"'),'\','\\'),'"}]},{"questionId":"a3f66c8f-4e34-4d1a-9568-b2d1d819c26b","sectionId":"9c8ee100-db8c-48c4-bda3-6ce76d6abd7c","responses":[{"responseId":"',outputs('Translate_AIRA_PrivacyRisks'),'"}]},{"questionId":"6d63beae-8681-4501-b6ef-c3736726b05c","sectionId":"9c8ee100-db8c-48c4-bda3-6ce76d6abd7c","responses":[{"responseId":"',outputs('Translate_AIRA_DataGovernance1'),'"}]}]'))
```

**Note on Q4 (Data Governance 1.0) and Q5 (Data Governance 2.0):**
These are multi-select with specific named options (not Yes/No). No Translate actions exist yet.

**Q4 — Data Governance 1.0 options:**
| Option | UUID |
|--------|------|
| Trained | `2e798235-56c3-422c-b1b8-40759d7546be` |
| Developed | `89274952-f5e0-4c60-8d8f-104a4f9212a6` |
| Other | `d677b266-ca71-4b9b-a80c-66883bae9c22` |
| N/A | `2fe9a446-0d8a-4dfd-ae03-5b2e156dcaff` |
| Not trained on personal data | `51e3c4e7-0d42-4852-b804-312bbd4b7c8e` |

**Q5 — Data Governance 2.0 options:**
| Option | UUID |
|--------|------|
| DPIA | `46904fe4-2db2-4d71-9996-e1ff39a07d41` |
| Designate DPO | `22ca1224-2a24-4ab8-a1e4-db053c177b44` |
| Oversight mechanisms | `d0af59a3-3c36-4e45-9c1b-044ff711a7e2` |
| Privacy-by-design | `f1a7a60e-44d1-4cf8-8c9f-389fb08e0d7a` |
| Data minimization | `4a5f1da4-8f49-45f2-8e59-9b8245dd9f16` |

---

## Section 4 — Transparency & Notice
sectionId: `86eb8a20-8833-40c9-b373-c3b1c68310b0`

- Q1 (MULTICHOICE Y/N/NA): Adequate notice — uses `Translate_AIRA_AdequateNotice`
- Q2 (MULTICHOICE Y/N/NA): Communication — uses `Translate_AIRA_Communication`
- Q3 (TEXTBOX): Communication mechanisms — triggerBody `AIRA_CommunicationMechanisms`
- Q4 (TEXTBOX): AI Benefits — triggerBody `AIRA_AIBenefits`

### Expression:

```
json(concat('[{"questionId":"9270ef3e-3577-4baf-b74d-758c86437915","sectionId":"86eb8a20-8833-40c9-b373-c3b1c68310b0","responses":[{"responseId":"',outputs('Translate_AIRA_AdequateNotice'),'"}]},{"questionId":"8c701b5c-408b-4074-b277-4b82d2611c8b","sectionId":"86eb8a20-8833-40c9-b373-c3b1c68310b0","responses":[{"responseId":"',outputs('Translate_AIRA_Communication'),'"}]},{"questionId":"a75bcc28-d7e3-49cb-b99a-76165bf18e75","sectionId":"86eb8a20-8833-40c9-b373-c3b1c68310b0","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_CommunicationMechanisms'],'N/A'),'"','\"'),'\','\\'),'"}]},{"questionId":"4f36e4cb-7f8a-44cb-834b-111f73810e1a","sectionId":"86eb8a20-8833-40c9-b373-c3b1c68310b0","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_AIBenefits'],'N/A'),'"','\"'),'\','\\'),'"}]}]'))
```

---

## Section 5 — Diversity, Non-discrimination and Fairness
sectionId: `0ac03872-da1c-438b-8546-05acab37c272`

All questions are MULTICHOICE Y/N/NA. All use existing Translate outputs.

### Expression:

```
json(concat('[{"questionId":"3691017a-80df-4471-aac9-0b8fef312f4e","sectionId":"0ac03872-da1c-438b-8546-05acab37c272","responses":[{"responseId":"',outputs('Translate_AIRA_UnfairBias1'),'"}]},{"questionId":"fa02ded6-02a0-4ff2-9f1b-39228ada887f","sectionId":"0ac03872-da1c-438b-8546-05acab37c272","responses":[{"responseId":"',outputs('Translate_AIRA_UnfairBias2'),'"}]},{"questionId":"11bb4901-df5d-4119-8082-9085e84e8fd1","sectionId":"0ac03872-da1c-438b-8546-05acab37c272","responses":[{"responseId":"',outputs('Translate_AIRA_UnfairBias3'),'"}]},{"questionId":"f03ccffb-dd68-45b8-b4e2-56a6298b13a6","sectionId":"0ac03872-da1c-438b-8546-05acab37c272","responses":[{"responseId":"',outputs('Translate_AIRA_UnfairBias4'),'"}]},{"questionId":"3b4609e0-eaef-49f5-aa0a-1f1533a3272d","sectionId":"0ac03872-da1c-438b-8546-05acab37c272","responses":[{"responseId":"',outputs('Translate_AIRA_Accessibility'),'"}]}]'))
```

---

## Section 6 — Security & Safety - AI
sectionId: `3950815a-a0c4-4059-871f-f04c599fe6ea`

- Q1 (MULTICHOICE Y/N/NA): Critical effects — uses `Translate_AIRA_CriticalEffects`
- Q2 (MULTICHOICE Y/N/NA): AI certified — uses `Translate_AIRA_AICertified`
- Q3 (MULTICHOICE multi-select): Vulnerabilities — needs Lookup

### Expression:

```
json(concat('[{"questionId":"267dc51e-e860-47e4-9c66-4b422e341c0d","sectionId":"3950815a-a0c4-4059-871f-f04c599fe6ea","responses":[{"responseId":"',outputs('Translate_AIRA_CriticalEffects'),'"}]},{"questionId":"93ca33f2-1f38-4f8e-9595-7e9e542f5fb0","sectionId":"3950815a-a0c4-4059-871f-f04c599fe6ea","responses":[{"responseId":"',outputs('Translate_AIRA_AICertified'),'"}]}]'))
```

**Note on Q3 (Vulnerabilities) — multi-select, no Translate yet:**
| Option | UUID |
|--------|------|
| Data poisoning | `6cc39282-c9a4-421f-bd6c-5e651d7a0b10` |
| Model evasion | `b4b4d50b-0a51-4f35-b7e0-19760620398c` |
| Model inversion | `56471e28-f767-4aad-bc72-bb7949ca163b` |
| None of the Above | `6a00f739-22e7-4d8f-bdd1-367543a0e970` |
| Other | `5ee754e1-0556-4d3b-8b86-7523fa6e9f52` |

---

## Section 7 — Associate Well-being
sectionId: `96f71bbe-2700-4165-9057-b4d3ecefad66`

- Q1 (MULTICHOICE Y/N/NA): Impact associates 1 — uses `Translate_AIRA_ImpactAssociates1`
- Q2 (MULTICHOICE Y/N/NA): Impact associates 2 — uses `Translate_AIRA_ImpactAssociates2`
- Q3 (TEXTBOX, hidden): Adopted measures — triggerBody `AIRA_AdoptedMeasures`

### Expression:

```
json(concat('[{"questionId":"28021ebb-a9b8-4a3d-a00a-b3d9bf5b62c7","sectionId":"96f71bbe-2700-4165-9057-b4d3ecefad66","responses":[{"responseId":"',outputs('Translate_AIRA_ImpactAssociates1'),'"}]},{"questionId":"4363aeb8-361a-4fff-a706-8e57ff1a007d","sectionId":"96f71bbe-2700-4165-9057-b4d3ecefad66","responses":[{"responseId":"',outputs('Translate_AIRA_ImpactAssociates2'),'"}]}]'))
```

---

## Section 8 — Privacy Risk Assessment (Completed by Privacy Practitioner)
sectionId: `cff1332d-96f3-44d4-af73-aca34a5e0cc7`

- Q1 (TEXTBOX): Applicable laws — triggerBody `AIRA_ApplicableLaws`
- Q2 (MULTICHOICE): Legal basis — needs Lookup
- Q3 (YESNO): Consequential Decision — uses `Translate_Common_AIConsequentialDecision`
- Q4 (YESNO): Restricted Info — uses `Translate_Common_AIRestrictedInfo`
- Q5 (YESNO): High Risk Volume — uses `Translate_Common_AIHighRiskVolume`
- Q6 (MULTICHOICE): Privacy risk rating — needs Lookup
- Q7 (TEXTBOX): Additional controls — triggerBody `AIRA_AdditionalControls`
- Q8 (TEXTBOX): AIEC approval — triggerBody `AIRA_AIECApproval`
- Q9 (TEXTBOX): SteerCo approval — triggerBody `AIRA_SteerCoApproval`

### Expression:

```
json(concat('[{"questionId":"4a9f3974-337f-4871-9fc4-2e17f4e7d3df","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_ApplicableLaws'],'N/A'),'"','\"'),'\','\\'),'"}]},{"questionId":"839263e1-8bf4-4b0a-8102-81dc61e4c01b","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"responseId":"',outputs('Translate_Common_AIConsequentialDecision'),'"}]},{"questionId":"72d521cd-dfc9-4413-9587-5fa0dc37b531","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"responseId":"',outputs('Translate_Common_AIRestrictedInfo'),'"}]},{"questionId":"19ffa46a-11f4-441f-8055-73ca3b8bd920","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"responseId":"',outputs('Translate_Common_AIHighRiskVolume'),'"}]},{"questionId":"cbeafc11-f7fb-40ad-95b1-595308da463e","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_AdditionalControls'],'N/A'),'"','\"'),'\','\\'),'"}]},{"questionId":"11865674-e078-4a10-a1ee-33b0c3445b0b","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_AIECApproval'],'N/A'),'"','\"'),'\','\\'),'"}]},{"questionId":"b1080bdb-bcb4-4903-9ff6-fcba1c8642bf","sectionId":"cff1332d-96f3-44d4-af73-aca34a5e0cc7","responses":[{"response":"',replace(replace(coalesce(triggerBody()?['AIRA_SteerCoApproval'],'N/A'),'"','\"'),'\','\\'),'"}]}]'))
```

**Q2 — Legal Basis options (no Translate yet):**
| Option | UUID |
|--------|------|
| Consent | `607299e9-90bd-4010-b792-6d8f008753ff` |
| Contract Performance | `ec547403-0104-4a51-bb39-648667f96149` |
| Legal Obligations | `2c9eed1b-4bd7-4d79-a949-21c33d5b31f9` |
| Vital Information / Life Protection | `1f7b66c9-fa3a-4f1a-bb87-82be033d4993` |
| Public Interest | `f9624efd-3ad9-4005-b16c-0104dfe76d3e` |
| *Legal Proceedings (Brazil Only) | `b1b7a764-41ee-42ab-a96b-773ac2f26eb7` |
| NotApplicable | `2b1cf8e9-db1f-4390-b45f-ec9516fabbd3` |

**Q6 — Privacy Risk Rating options (no Translate yet):**
| Option | UUID |
|--------|------|
| 5 (High) | `ed9ad303-f8d5-4b78-8aa7-bcc22e432331` |
| 4 | `c287c052-1b2b-45a1-ae98-3df957e79dd4` |
| 3 | `8c8b4872-a08c-4363-8d18-7d4d8bb3a797` |
| 2 | `9d6075c8-8a60-4d5c-92ed-a750f54143be` |
| 1 (Low) | `b33ad8d2-ce28-4ff1-86d7-93b19210b8c1` |

---

## CRITICAL DIFFERENCE: `responseId` vs `response`

- **MULTICHOICE / YESNO** questions: use `"responseId": "uuid"` — the UUID of the selected option
- **TEXTBOX** questions: use `"response": "text"` — the plain text value

The old flow was sending `"response": "Yes"` (plain text) for MULTICHOICE questions. That's wrong. It must be `"responseId": "0e6be695-018e-41d1-b27f-c514a781e0d3"` (the UUID for the "Yes" option on that specific question).

The existing Translate actions already convert Yes/No/true/false to the correct UUIDs, so the expressions above using `outputs('Translate_...')` will produce the right UUIDs.

---

## Flow Execution Order

```
Create_AIRA_Assessment
  -> Set AIRAAssessmentId
    -> Delay (3 sec)
      -> Submit_AIRA_Section_1
        -> Submit_AIRA_Section_2
          -> Submit_AIRA_Section_3
            -> Submit_AIRA_Section_4
              -> Submit_AIRA_Section_5
                -> Submit_AIRA_Section_6
                  -> Submit_AIRA_Section_7
                    -> Submit_AIRA_Section_8
```

Each HTTP POST action:
- Method: POST
- URI: `@concat('https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/',variables('AIRAAssessmentId'),'/sections/{sectionId}/questions/responses')`
  (replace `{sectionId}` with the actual sectionId for that section)
- Headers: Authorization: `Bearer {AccessToken}`, Content-Type: `application/json`
- Body: The expression from above
