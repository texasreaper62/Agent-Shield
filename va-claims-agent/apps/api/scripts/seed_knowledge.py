"""
Seed the knowledge base with 38 CFR Part 4 Rating Schedule data.

This script populates the database with:
- Common CFR sections
- Diagnostic codes and rating criteria
- Knowledge articles about VA claims

Source: 38 CFR Part 4 - Schedule for Rating Disabilities
https://www.ecfr.gov/current/title-38/chapter-I/part-4
"""
import asyncio
from uuid import uuid4
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

import sys
sys.path.append('..')

from config import settings
from models.knowledge import CFRSection, RatingCriteria, KnowledgeArticle

engine = create_async_engine(settings.DATABASE_URL)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# 38 CFR Part 4 - Rating Schedule Sections
CFR_SECTIONS = [
    # Musculoskeletal System
    {
        "part": 4,
        "section": "4.71a",
        "diagnostic_code": "5260",
        "section_title": "Limitation of Flexion of the Leg",
        "full_text": """
5260 Leg, limitation of flexion of:
Flexion limited to 15° - 30%
Flexion limited to 30° - 20%
Flexion limited to 45° - 10%
Flexion limited to 60° - 0%
        """,
        "body_system": "Musculoskeletal",
        "condition_category": "Knee",
        "rating_percentages": [
            {"percentage": 30, "criteria": "Flexion limited to 15 degrees"},
            {"percentage": 20, "criteria": "Flexion limited to 30 degrees"},
            {"percentage": 10, "criteria": "Flexion limited to 45 degrees"},
            {"percentage": 0, "criteria": "Flexion limited to 60 degrees"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR7dc82240e82dea6/section-4.71a"
    },
    {
        "part": 4,
        "section": "4.71a",
        "diagnostic_code": "5261",
        "section_title": "Limitation of Extension of the Leg",
        "full_text": """
5261 Leg, limitation of extension of:
Extension limited to 45° - 50%
Extension limited to 30° - 40%
Extension limited to 20° - 30%
Extension limited to 15° - 20%
Extension limited to 10° - 10%
Extension limited to 5° - 0%
        """,
        "body_system": "Musculoskeletal",
        "condition_category": "Knee",
        "rating_percentages": [
            {"percentage": 50, "criteria": "Extension limited to 45 degrees"},
            {"percentage": 40, "criteria": "Extension limited to 30 degrees"},
            {"percentage": 30, "criteria": "Extension limited to 20 degrees"},
            {"percentage": 20, "criteria": "Extension limited to 15 degrees"},
            {"percentage": 10, "criteria": "Extension limited to 10 degrees"},
            {"percentage": 0, "criteria": "Extension limited to 5 degrees"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR7dc82240e82dea6/section-4.71a"
    },
    {
        "part": 4,
        "section": "4.71a",
        "diagnostic_code": "5003",
        "section_title": "Arthritis, Degenerative",
        "full_text": """
5003 Arthritis, degenerative (hypertrophic or osteoarthritis):
Degenerative arthritis established by X-ray findings will be rated on the basis of limitation
of motion under the appropriate diagnostic codes for the specific joint or joints involved.
When however, the limitation of motion of the specific joint or joints involved is
noncompensable under the appropriate diagnostic codes, a rating of 10 percent is for
application for each such major joint or group of minor joints affected by limitation of
motion, to be combined, not added under diagnostic code 5003.
        """,
        "body_system": "Musculoskeletal",
        "condition_category": "Arthritis",
        "rating_percentages": [
            {"percentage": 20, "criteria": "X-ray evidence of involvement of 2 or more major joints or 2 or more minor joint groups, with occasional incapacitating exacerbations"},
            {"percentage": 10, "criteria": "X-ray evidence of involvement of 2 or more major joints or 2 or more minor joint groups"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR7dc82240e82dea6/section-4.71a"
    },
    # Mental Disorders
    {
        "part": 4,
        "section": "4.130",
        "diagnostic_code": "9411",
        "section_title": "Post-Traumatic Stress Disorder (PTSD)",
        "full_text": """
9411 Post-traumatic stress disorder:
100% - Total occupational and social impairment
70% - Occupational and social impairment, with deficiencies in most areas
50% - Occupational and social impairment with reduced reliability and productivity
30% - Occupational and social impairment with occasional decrease in work efficiency
10% - Occupational and social impairment due to mild or transient symptoms
0% - A mental condition has been formally diagnosed, but symptoms are not severe enough
        """,
        "body_system": "Mental Disorders",
        "condition_category": "PTSD",
        "rating_percentages": [
            {"percentage": 100, "criteria": "Total occupational and social impairment, due to such symptoms as: gross impairment in thought processes or communication; persistent delusions or hallucinations; grossly inappropriate behavior; persistent danger of hurting self or others; intermittent inability to perform activities of daily living; disorientation to time or place; memory loss for names of close relatives, own occupation, or own name"},
            {"percentage": 70, "criteria": "Occupational and social impairment, with deficiencies in most areas, such as work, school, family relations, judgment, thinking, or mood"},
            {"percentage": 50, "criteria": "Occupational and social impairment with reduced reliability and productivity due to such symptoms as: flattened affect; circumstantial, circumlocutory, or stereotyped speech; panic attacks more than once a week; difficulty in understanding complex commands; impairment of short- and long-term memory"},
            {"percentage": 30, "criteria": "Occupational and social impairment with occasional decrease in work efficiency and intermittent periods of inability to perform occupational tasks"},
            {"percentage": 10, "criteria": "Occupational and social impairment due to mild or transient symptoms which decrease work efficiency and ability to perform occupational tasks only during periods of significant stress"},
            {"percentage": 0, "criteria": "A mental condition has been formally diagnosed, but symptoms are not severe enough either to interfere with occupational and social functioning or to require continuous medication"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR4a6e56bc17e95ba/section-4.130"
    },
    # Hearing Loss
    {
        "part": 4,
        "section": "4.85",
        "diagnostic_code": "6100",
        "section_title": "Hearing Impairment",
        "full_text": """
6100 Hearing impairment:
Evaluations of hearing loss range from noncompensable to 100 percent based on organic
impairment of hearing acuity as measured by the results of controlled speech discrimination
tests together with the average hearing threshold level as measured by pure tone audiometry
tests in the frequencies 1000, 2000, 3000 and 4000 cycles per second.
        """,
        "body_system": "Auditory",
        "condition_category": "Hearing Loss",
        "rating_percentages": [
            {"percentage": 100, "criteria": "Bilateral hearing loss at Level XI"},
            {"percentage": 80, "criteria": "See Table VI and VII for specific combinations"},
            {"percentage": 60, "criteria": "See Table VI and VII for specific combinations"},
            {"percentage": 40, "criteria": "See Table VI and VII for specific combinations"},
            {"percentage": 20, "criteria": "See Table VI and VII for specific combinations"},
            {"percentage": 10, "criteria": "See Table VI and VII for specific combinations"},
            {"percentage": 0, "criteria": "Hearing within normal limits or mild hearing loss"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR9bf27ed55502db8/section-4.85"
    },
    # Tinnitus
    {
        "part": 4,
        "section": "4.87",
        "diagnostic_code": "6260",
        "section_title": "Tinnitus",
        "full_text": """
6260 Tinnitus, recurrent:
10% - Recurrent tinnitus (maximum rating)

Note: A separate evaluation for tinnitus may be combined with an evaluation under
diagnostic codes 6100, 6200, 6201, 6202, or 6204.
        """,
        "body_system": "Auditory",
        "condition_category": "Tinnitus",
        "rating_percentages": [
            {"percentage": 10, "criteria": "Recurrent tinnitus (this is the maximum schedular rating)"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR9bf27ed55502db8/section-4.87"
    },
    # Back Conditions
    {
        "part": 4,
        "section": "4.71a",
        "diagnostic_code": "5237",
        "section_title": "Lumbosacral Strain",
        "full_text": """
5237 Lumbosacral or cervical strain:
With or without symptoms such as pain (whether or not it radiates), stiffness, or aching
in the area of the spine affected by residuals of injury or disease:

100% - Unfavorable ankylosis of the entire spine
50% - Unfavorable ankylosis of the entire thoracolumbar spine
40% - Unfavorable ankylosis of the entire cervical spine; or, forward flexion of the
      thoracolumbar spine 30 degrees or less; or, favorable ankylosis of the entire
      thoracolumbar spine
30% - Forward flexion of the cervical spine 15 degrees or less; or, favorable ankylosis
      of the entire cervical spine
20% - Forward flexion of the thoracolumbar spine greater than 30 degrees but not greater
      than 60 degrees
10% - Forward flexion of the thoracolumbar spine greater than 60 degrees but not greater
      than 85 degrees
        """,
        "body_system": "Musculoskeletal",
        "condition_category": "Spine",
        "rating_percentages": [
            {"percentage": 100, "criteria": "Unfavorable ankylosis of the entire spine"},
            {"percentage": 50, "criteria": "Unfavorable ankylosis of the entire thoracolumbar spine"},
            {"percentage": 40, "criteria": "Forward flexion of the thoracolumbar spine 30 degrees or less; or, favorable ankylosis of the entire thoracolumbar spine"},
            {"percentage": 20, "criteria": "Forward flexion of the thoracolumbar spine greater than 30 degrees but not greater than 60 degrees"},
            {"percentage": 10, "criteria": "Forward flexion of the thoracolumbar spine greater than 60 degrees but not greater than 85 degrees"},
        ],
        "ecfr_url": "https://www.ecfr.gov/current/title-38/chapter-I/part-4/subpart-B/subject-group-ECFR7dc82240e82dea6/section-4.71a"
    },
]

# Knowledge Articles
KNOWLEDGE_ARTICLES = [
    {
        "title": "Understanding Direct Service Connection",
        "slug": "direct-service-connection",
        "category": "service-connection",
        "content": """
# Direct Service Connection

Direct service connection is the most straightforward way to establish that a current
disability is related to military service.

## Three Elements Required

To establish direct service connection, you must show:

1. **In-Service Event**: Evidence that something happened during your military service
   (injury, illness, exposure, etc.)

2. **Current Disability**: A current medical diagnosis of the condition

3. **Nexus**: A medical opinion linking the current condition to the in-service event

## Types of Evidence

- Service treatment records
- Personnel records
- Buddy statements
- Medical expert opinions (nexus letters)
- VA C&P exam results

## Important CFR References

- 38 CFR § 3.303 - Principles relating to service connection
- 38 CFR § 3.304 - Direct service connection; wartime and peacetime
        """,
        "summary": "Direct service connection requires proof of an in-service event, current disability, and a nexus between them.",
        "keywords": ["direct", "service connection", "nexus", "in-service event"],
        "cfr_references": ["3.303", "3.304"],
    },
    {
        "title": "Secondary Service Connection",
        "slug": "secondary-service-connection",
        "category": "service-connection",
        "content": """
# Secondary Service Connection

Secondary service connection allows you to claim benefits for a disability that was
caused or aggravated by an already service-connected condition.

## Requirements

1. You must have an existing service-connected disability
2. A current diagnosed condition
3. Medical evidence showing the new condition was:
   - Caused by the service-connected condition, OR
   - Aggravated (permanently worsened) by the service-connected condition

## Common Secondary Conditions

- Depression/anxiety secondary to chronic pain conditions
- Peripheral neuropathy secondary to diabetes
- Sleep apnea secondary to PTSD
- Knee/hip problems secondary to back conditions

## Key CFR Reference

38 CFR § 3.310 - Disabilities that are proximately due to, or aggravated by,
service-connected disease or injury
        """,
        "summary": "Secondary service connection allows claims for conditions caused or aggravated by existing service-connected disabilities.",
        "keywords": ["secondary", "aggravation", "caused by", "proximately due"],
        "cfr_references": ["3.310"],
    },
    {
        "title": "Presumptive Service Connection",
        "slug": "presumptive-service-connection",
        "category": "service-connection",
        "content": """
# Presumptive Service Connection

Presumptive service connection allows veterans to receive benefits for certain
conditions without proving a direct link to service.

## Types of Presumptions

### Agent Orange Presumption
Veterans who served in Vietnam (1962-1975) are presumed exposed to Agent Orange.
Presumptive conditions include:
- Type 2 diabetes
- Ischemic heart disease
- Parkinson's disease
- Certain cancers

### Gulf War Presumption
Veterans who served in Southwest Asia may claim presumptive conditions for
undiagnosed illnesses and medically unexplained chronic multisymptom illnesses.

### Chronic Disease Presumption
Certain chronic diseases that manifest within one year of discharge are presumed
service-connected:
- Arthritis
- Hypertension
- Diabetes mellitus
- Psychoses

## Key CFR References

- 38 CFR § 3.307 - Presumptive service connection for chronic diseases
- 38 CFR § 3.309 - Disease subject to presumptive service connection
        """,
        "summary": "Presumptive conditions allow service connection without direct evidence based on service location, era, or timing.",
        "keywords": ["presumptive", "Agent Orange", "Gulf War", "chronic disease"],
        "cfr_references": ["3.307", "3.309"],
    },
    {
        "title": "Fee Limitations Under 38 CFR § 14.636",
        "slug": "fee-limitations",
        "category": "legal",
        "content": """
# Attorney and Agent Fee Limitations

## Critical Rule: No Fees on Initial Claims

Under 38 CFR § 14.636(c), attorneys and agents CANNOT charge fees for:
- Original claims (first-time claims for a condition)
- Claims for increase when no prior denial exists

## When Fees ARE Allowed

Fees may be charged when:
1. A Notice of Disagreement (NOD) has been filed
2. The claim has been denied and is being appealed
3. A fee agreement is filed with the VA

## Fee Limits

- Maximum fee is typically 20% of past-due benefits
- Some exceptions allow up to 33 1/3%
- Fee must be "reasonable"

## Compliance Requirements

This system automatically:
- Flags initial claims where fees are prohibited
- Tracks fee agreement status
- Prevents fee collection on prohibited claims

## Reference

38 CFR § 14.636 - Payment of fees for representation
        """,
        "summary": "Fees cannot be charged on initial claims per 38 CFR § 14.636. Fees are only allowed after a Notice of Disagreement.",
        "keywords": ["fees", "attorney", "agent", "14.636", "initial claim"],
        "cfr_references": ["14.636"],
    },
]


async def seed_database():
    """Seed the knowledge base with CFR data."""
    async with async_session() as session:
        # Add CFR Sections
        for section_data in CFR_SECTIONS:
            section = CFRSection(
                id=uuid4(),
                title=38,
                part=section_data["part"],
                section=section_data["section"],
                diagnostic_code=section_data.get("diagnostic_code"),
                section_title=section_data["section_title"],
                full_text=section_data["full_text"],
                body_system=section_data.get("body_system"),
                condition_category=section_data.get("condition_category"),
                rating_percentages=section_data.get("rating_percentages"),
                ecfr_url=section_data.get("ecfr_url"),
            )
            session.add(section)

            # Add rating criteria
            for rating in section_data.get("rating_percentages", []):
                criteria = RatingCriteria(
                    id=uuid4(),
                    cfr_section_id=section.id,
                    diagnostic_code=section_data.get("diagnostic_code", ""),
                    condition_name=section_data["section_title"],
                    rating_percentage=rating["percentage"],
                    criteria_description=rating["criteria"],
                )
                session.add(criteria)

        # Add Knowledge Articles
        for article_data in KNOWLEDGE_ARTICLES:
            article = KnowledgeArticle(
                id=uuid4(),
                title=article_data["title"],
                slug=article_data["slug"],
                category=article_data["category"],
                content=article_data["content"],
                summary=article_data.get("summary"),
                keywords=article_data.get("keywords"),
                cfr_references=article_data.get("cfr_references"),
                is_published=True,
            )
            session.add(article)

        await session.commit()
        print(f"Seeded {len(CFR_SECTIONS)} CFR sections and {len(KNOWLEDGE_ARTICLES)} articles")


if __name__ == "__main__":
    asyncio.run(seed_database())
