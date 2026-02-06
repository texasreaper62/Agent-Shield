# Step-by-Step: Fix Trust Form Scope in Power Automate

## BEFORE YOU START
- This guide modifies the existing Trust Form scope to add `sectionId` to each section submission
- You will need to add new variables and new actions
- Do NOT delete any existing Translate_Trust compose actions — those stay as-is
- Total time: ~30 minutes

---

## PART 1: Add New Variables (Outside the Scope — at the top of the flow)

Variables in Power Automate MUST be initialized at the top level of the flow, NOT inside a Scope or Condition. Add these BEFORE the existing scope.

1. Click **+ New step** at the TOP of your flow (before the TRANSLATE_TRUST scope)
2. Search for **"Initialize variable"**
3. Create **6 new variables**, one at a time:

| Name | Type | Initial Value |
|------|------|--------------|
| `TrustSection1Id` | String | *(leave blank)* |
| `TrustSection2Id` | String | *(leave blank)* |
| `TrustSection3Id` | String | *(leave blank)* |
| `TrustSection4Id` | String | *(leave blank)* |
| `TrustSection5Id` | String | *(leave blank)* |
| `TrustSection6Id` | String | *(leave blank)* |

> **Tip:** You can place these right next to your existing Initialize Variable actions for `PIAAssessmentId`, `AccessToken`, etc.

---

## PART 2: Add the GET Assessment Step (Inside the Scope)

This step retrieves the assessment structure so we can grab the section IDs.

1. Inside the Condition (the `true` branch), find the **Delay** action
2. Click the **+** button AFTER the Delay step
3. Add a new action → search **"HTTP"** → select **HTTP**
4. Rename it to: **`GET_Assessment_Structure`**
5. Fill in:
   - **Method:** `GET`
   - **URI:** Click in the field and type:
     ```
     https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/
     ```
     Then click **Dynamic content** → select **PIAAssessmentId** (it will append to the URL)
   - **Headers:**
     | Key | Value |
     |-----|-------|
     | `Authorization` | `Bearer ` then Dynamic content → **AccessToken** |

   The full URI should look like:
   ```
   https://mvw-global-privacy.my.onetrust.com/api/assessment/v2/assessments/@{variables('PIAAssessmentId')}
   ```

6. Click **Save**

---

## PART 3: Add 6 "Set Variable" Steps (After the GET step)

These pull each section ID out of the GET response. Add them ONE AFTER ANOTHER in sequence.

### Step 3a: Set TrustSection1Id
1. Click **+** after `GET_Assessment_Structure`
2. Search **"Set variable"** → select it
3. **Name:** select `TrustSection1Id` from the dropdown
4. **Value:** Click in the Value field, then switch to **Expression** tab (not Dynamic content)
5. Paste this expression EXACTLY:
   ```
   body('GET_Assessment_Structure')?['sectionHeaders']?[0]?['sectionId']
   ```
6. Click **OK**, then **Save**

### Step 3b: Set TrustSection2Id
1. Click **+** after `Set TrustSection1Id`
2. **Set variable** → Name: `TrustSection2Id`
3. Expression:
   ```
   body('GET_Assessment_Structure')?['sectionHeaders']?[1]?['sectionId']
   ```

### Step 3c: Set TrustSection3Id
1. Click **+** after `Set TrustSection2Id`
2. **Set variable** → Name: `TrustSection3Id`
3. Expression:
   ```
   body('GET_Assessment_Structure')?['sectionHeaders']?[2]?['sectionId']
   ```

### Step 3d: Set TrustSection4Id
1. Click **+** after `Set TrustSection3Id`
2. **Set variable** → Name: `TrustSection4Id`
3. Expression:
   ```
   body('GET_Assessment_Structure')?['sectionHeaders']?[3]?['sectionId']
   ```

### Step 3e: Set TrustSection5Id
1. Click **+** after `Set TrustSection4Id`
2. **Set variable** → Name: `TrustSection5Id`
3. Expression:
   ```
   body('GET_Assessment_Structure')?['sectionHeaders']?[4]?['sectionId']
   ```

### Step 3f: Set TrustSection6Id
1. Click **+** after `Set TrustSection5Id`
2. **Set variable** → Name: `TrustSection6Id`
3. Expression:
   ```
   body('GET_Assessment_Structure')?['sectionHeaders']?[5]?['sectionId']
   ```

> **IMPORTANT:** If the GET response includes a "Welcome" section as the first item, all indices shift by +1 (use [1] through [6] instead of [0] through [5]). Run the GET step once and check the output to verify.

---

## PART 4: Modify Each Submit_Trust_Section Action

For EACH of the 6 Submit_Trust_Section actions, you need to:
1. Change the Body to use the `@json(concat(...))` expression pattern
2. Add `sectionId` as the first field in the JSON body

### How to edit the body of an HTTP action:

1. Click on the **Submit_Trust_Section_N** action to expand it
2. Click in the **Body** field
3. **Delete everything** currently in the Body field
4. Switch to the **Expression** tab
5. Paste the new expression (provided below for each section)
6. Click **OK**

---

### Section 1 Body — Replace with this expression:

```
json(concat('{"sectionId":"',variables('TrustSection1Id'),'","responses":[{"questionId":"ebd86e1d-810a-4400-bd2c-e1d9ed462eec","values":["',coalesce(triggerBody()?['ApplicationService'],'N/A'),'"]},{"questionId":"3f1266c0-c7c0-49fe-a364-b0fe8ffedafc","values":["',outputs('Translate_Trust_S1Q3_Processing_Activity'),'"]},{"questionId":"e5271835-3e89-42b4-b4f5-17346a31c6c4","values":["',coalesce(triggerBody()?['ServiceDescription'],'N/A'),'"]},{"questionId":"38158f80-c4de-443e-bc6c-64ac5bfe0bd7","values":["',outputs('Translate_Trust_S1Q5_Purpose_for_Processing'),'"]}]}'))
```

> **Note:** When pasting into the Expression tab, make sure there is NO `@` symbol at the beginning. The Expression tab adds it automatically.

---

### Section 2 Body — Replace with this expression:

```
json(concat('{"sectionId":"',variables('TrustSection2Id'),'","responses":[{"questionId":"54609d93-27f3-47b9-9405-1fadd6d9f2bb","values":["',outputs('Translate_Trust_S2Q2_Additional_Data_Elements'),'"]},{"questionId":"11a1335f-78df-4e8d-9d38-3566f383fb24","values":["',outputs('Translate_Trust_S2Q4_Data_Subject_Region'),'"]},{"questionId":"edc80ecb-35b5-46b6-abb5-3631aefa51a0","values":["',coalesce(triggerBody()?['Common_Subprocessors'],'N/A'),'"]},{"questionId":"5b6ca434-d65d-43ec-941f-fb6ba2fe2e89","values":["',outputs('Translate_Trust_S2Q6_Hosting_Arrangement'),'"]},{"questionId":"4f3e7302-e511-4875-a755-3371bbb9001e","values":["',outputs('Translate_Trust_S2Q7_Hosting_Provider'),'"]},{"questionId":"c2ccef7c-e055-4148-add7-5d9d1cb6f1a8","values":["',outputs('Translate_Trust_S2Q8_Instance_Location'),'"]},{"questionId":"2221e756-6f3f-4da4-9d82-0e45f3a50782","values":["',outputs('Translate_Trust_S2Q9_Third_Party_or_Service_Provider'),'"]},{"questionId":"967cc49f-ef1c-4daf-98de-dbbb07ffe7c8","values":["',outputs('Translate_Trust_S2Q10_Sharing_of_Data'),'"]},{"questionId":"816ca963-6cfd-4d57-bb7c-1447bb5b6452","values":["',outputs('Translate_Trust_S2Q11_Selling_of_Data'),'"]},{"questionId":"8fea67aa-736f-46e9-b81f-903e678686da","values":["',outputs('Translate_Trust_S2Q12_GLBA'),'"]},{"questionId":"47d3c0be-edb1-46f3-8dcc-8546b6370fa4","values":["',outputs('Translate_Trust_S2Q13_Web_Mobile_Based'),'"]},{"questionId":"fba3cd7a-6dd9-418f-a5ba-5ae02e5344c2","values":["',outputs('Translate_Trust_S2Q14_User_Interface'),'"]},{"questionId":"35d06d92-6893-4403-8326-da8d8f4b06d6","values":["',outputs('Translate_Trust_S2Q15_WCAG_Compliance'),'"]},{"questionId":"3919a107-bd86-4107-8aa1-9c17547f011b","values":["',outputs('Translate_Trust_S2Q16_Uses_Cookies'),'"]},{"questionId":"5d5f5271-5c5f-498a-af85-8ff6e5ff11d9","values":["',outputs('Translate_Trust_S2Q17_OneTrust_Integration'),'"]},{"questionId":"3a455264-fe30-4cfc-ab2f-0204bf0efcde","values":["',outputs('Translate_Trust_S2Q18_Google_Analytics'),'"]},{"questionId":"9a40e9cd-7037-4161-8ef3-359abce8c575","values":["',outputs('Translate_Trust_S2Q19_Children_Under_16'),'"]},{"questionId":"aed7a4fd-da58-45db-9cda-40a7d0380ac4","values":["',outputs('Translate_Trust_S2Q20_Automated_Decision_Making'),'"]},{"questionId":"01269fe4-b394-4d85-abe4-56398ae5dc7f","values":["',outputs('Translate_Trust_S2Q21_AI_Tools'),'"]},{"questionId":"1928e07f-f73a-4c9a-8afb-6d7f619b8b06","values":["',coalesce(triggerBody()?['AIRA_AIDescription'],'N/A'),'"]},{"questionId":"75a1cd09-6005-4571-9b91-2d3761b200a1","values":["',outputs('Translate_Trust_S2Q23_Privacy_Notice'),'"]},{"questionId":"a8570434-8e7f-45ed-a5a9-f9a720a2b852","values":["',outputs('Translate_Trust_S2Q24_Privacy_Due_Diligence'),'"]}]}'))
```

---

### Section 3 Body — Replace with this expression:

```
json(concat('{"sectionId":"',variables('TrustSection3Id'),'","responses":[{"questionId":"38b862a5-2cb4-4310-bb30-09e80eb6ae34","values":["',coalesce(triggerBody()?['VRP_SystemsCollect'],''),'"]},{"questionId":"ff3b21b7-0f8e-4747-8b3b-fbf81db48f76","values":["',coalesce(triggerBody()?['VRP_SystemsProcess'],''),'"]},{"questionId":"df26c544-b4a9-4028-b5d3-7339a1591331","values":["',coalesce(triggerBody()?['VRP_SystemsTransfer'],''),'"]},{"questionId":"98a06c1b-ee40-498c-ae8e-8555e2adbf43","values":["',outputs('Translate_Trust_S3Q4_Transfer_to_Affiliates'),'"]},{"questionId":"5e59bdc8-c40f-47e4-bf66-15b0724cb394","values":["',outputs('Translate_Trust_S3Q5_Data_Shared_Outside_Country'),'"]},{"questionId":"9c605029-b56a-4f84-8db9-ef5d095d18c3","values":["',coalesce(triggerBody()?['Common_DataTransferRegions'],''),'"]}]}'))
```

---

### Section 4 Body — Replace with this expression:

```
json(concat('{"sectionId":"',variables('TrustSection4Id'),'","responses":[{"questionId":"3a4608c7-2785-41e0-9ddd-23ece9ddea13","values":["',outputs('Translate_Trust_S4Q1_Applicable_Laws'),'"]},{"questionId":"403f3d9e-6d85-43e3-bb86-8d9557974848","values":["',outputs('Translate_Trust_S4Q2_Legal_Basis'),'"]},{"questionId":"bfbebb79-f95c-4279-9679-3a77fbfeec9d","values":["',outputs('Translate_Trust_S4Q3_Risk_Impact_to_Rights'),'"]},{"questionId":"ec8bbe36-f742-4ac8-b846-27cf3aa41434","values":["',outputs('Translate_Trust_S4Q4_Legitimate_Interests_Outweighed'),'"]},{"questionId":"84105b5d-4f4e-404c-9efe-9c9f523b258c","values":["',outputs('Translate_Trust_S4Q5_Data_Operations'),'"]},{"questionId":"4b749a58-7351-47d8-b81d-d115dac35300","values":["',outputs('Translate_Trust_S4Q6_Consent_Required'),'"]},{"questionId":"551c4978-525a-49f8-9cc7-cfe0dc6cdb0e","values":["',outputs('Translate_Trust_S4Q7_Consent_Withdrawal_Steps'),'"]},{"questionId":"ff297869-05d9-4cc5-807d-68bb6ec0bb7d","values":["',outputs('Translate_Trust_S4Q8_Parental_Consent'),'"]},{"questionId":"c1dab02b-2648-49b0-ae12-0d8eaa087458","values":["',outputs('Translate_Trust_S4Q9_CA_Under_16_Consent'),'"]},{"questionId":"6a88c2a7-eac2-42a7-bb25-429c6b42c829","values":["',coalesce(triggerBody()?['Common_NoticeToDataSubject'],''),'"]},{"questionId":"1074c38c-9cb3-42dd-98bd-296d6ac75f83","values":["',outputs('Translate_Trust_S4Q11_Surveillance'),'"]}]}'))
```

---

### Section 5 Body — Replace with this expression:

```
json(concat('{"sectionId":"',variables('TrustSection5Id'),'","responses":[{"questionId":"1874fdf8-b276-4215-915f-3250463a8557","values":["',outputs('Translate_Trust_S5Q1_Privacy_Contract_Required'),'"]},{"questionId":"d2090348-7dd2-4874-9675-46ab20270189","values":["',outputs('Translate_Trust_S5Q2_Privacy_Contract_Doc_Type'),'"]}]}'))
```

---

### Section 6 Body — Replace with this expression:

```
json(concat('{"sectionId":"',variables('TrustSection6Id'),'","responses":[{"questionId":"f035f24f-9b60-483f-a8b3-49212b372db9","values":["',coalesce(triggerBody()?['AdditionalContext'],''),'"]}]}'))
```

---

## PART 5: Update the "Runs After" Order

Make sure the actions run in this order. For each action, click the **three dots (...)** → **Configure run after** to set what it runs after:

```
Create_PIA_Assessment
    ↓
Set_variable (PIAAssessmentId)          runs after: Create_PIA_Assessment
    ↓
Delay (3 seconds)                       runs after: Set_variable
    ↓
GET_Assessment_Structure          ★NEW  runs after: Delay
    ↓
Set TrustSection1Id               ★NEW  runs after: GET_Assessment_Structure
    ↓
Set TrustSection2Id               ★NEW  runs after: Set TrustSection1Id
    ↓
Set TrustSection3Id               ★NEW  runs after: Set TrustSection2Id
    ↓
Set TrustSection4Id               ★NEW  runs after: Set TrustSection3Id
    ↓
Set TrustSection5Id               ★NEW  runs after: Set TrustSection4Id
    ↓
Set TrustSection6Id               ★NEW  runs after: Set TrustSection5Id
    ↓
Submit_Trust_Section_1       ★MODIFIED  runs after: Set TrustSection6Id
    ↓
Submit_Trust_Section_2       ★MODIFIED  runs after: Submit_Trust_Section_1
    ↓
Submit_Trust_Section_3       ★MODIFIED  runs after: Submit_Trust_Section_2
    ↓
Submit_Trust_Section_4       ★MODIFIED  runs after: Submit_Trust_Section_3
    ↓
Submit_Trust_Section_5       ★MODIFIED  runs after: Submit_Trust_Section_4
    ↓
Submit_Trust_Section_6       ★MODIFIED  runs after: Submit_Trust_Section_5
```

---

## PART 6: Save and Test

1. Click **Save** in the top-left
2. If Power Automate shows validation errors:
   - Check that all 6 TrustSectionNId variables were initialized at the TOP of the flow
   - Check that expression fields don't have a stray `@` at the beginning
   - Check that all Translate_Trust compose action names match exactly
3. **Test with a single run:**
   - Click **Test** → **Manually** → **Run flow**
   - After the run, click into the run history
   - Check the output of `GET_Assessment_Structure` — verify `sectionHeaders` is an array with 6 items
   - Check the output of each `Set TrustSectionNId` — verify each has a UUID
   - Check `Submit_Trust_Section_1` — if it returns 200, the fix worked!

---

## TROUBLESHOOTING

### "The variable 'TrustSection1Id' was not found"
→ You didn't add the Initialize Variable actions at the TOP of the flow. Variables cannot be initialized inside a Scope or Condition.

### Section IDs are all null/empty
→ The `sectionHeaders` array may start with a Welcome section at index [0]. Check the GET output and shift all indices by +1 if needed (use [1] through [6] instead of [0] through [5]).

### Still getting 400 after adding sectionId
→ Try these in order:
1. Check the assessment status in the GET response — if `"status": "COMPLETED"`, create a fresh one
2. Try the endpoint path `/submit/responses` instead of `/responses`
3. For MULTICHOICE questions, try sending the option TEXT instead of UUID

### Expression editor won't accept the expression
→ Make sure you're on the **Expression** tab (not Dynamic Content tab). The expression should NOT start with `@` — Power Automate adds that automatically.

### The GET step fails with 401 or 403
→ The Bearer token may have expired. Make sure the token is still valid at this point in the flow.
