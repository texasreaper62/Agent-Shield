# VA Claims Agent

AI-powered VA disability claims processing system with citation enforcement and regulatory compliance.

## Overview

This system helps veterans and their representatives process VA disability claims by:
- Extracting evidence from uploaded documents
- Identifying potential claims and service connections
- Auto-filling VA forms with cited sources
- Providing attorney review workflow
- Submitting to VA Benefits Intake API

## Critical Rules

1. **NO CITATION = NO OUTPUT**: Every AI-generated fact must cite evidence
2. **HUMAN APPROVES SUBMISSION**: Never auto-submit to VA
3. **FEE COMPLIANCE**: Block fee collection on initial claims (38 CFR §14.636)
4. **NEVER COMMIT SECRETS**: All credentials in .env files, not code

## Architecture

```
va-claims-agent/
├── apps/
│   ├── api/              # FastAPI backend
│   │   ├── agents/       # AI agents with citation enforcement
│   │   ├── models/       # SQLAlchemy models
│   │   ├── routers/      # API endpoints
│   │   └── services/     # External services
│   └── web/              # Next.js frontend
├── services/
│   └── workers/          # Background processors
├── infrastructure/
│   └── terraform/        # Azure infrastructure
└── packages/             # Shared code
```

## Tech Stack

- **Backend**: Python FastAPI
- **Frontend**: Next.js TypeScript
- **Database**: PostgreSQL with pgvector
- **Storage**: Azure Blob Storage
- **Queue**: Azure Service Bus
- **OCR**: Azure Document Intelligence
- **AI**: Claude Sonnet/Haiku (Anthropic)
- **Infrastructure**: Terraform on Azure

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker (optional)
- Azure account
- Anthropic API key

### Setup

1. Clone the repository:
```bash
git clone https://github.com/texasreaper62/va-claims-agent.git
cd va-claims-agent
```

2. Copy environment files:
```bash
cp .env.example .env
# Edit .env with your credentials
```

3. Install dependencies:
```bash
# API
cd apps/api
pip install -r requirements.txt

# Web
cd apps/web
npm install
```

4. Deploy infrastructure:
```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars
terraform init
terraform apply
```

5. Run database migrations:
```bash
cd apps/api
alembic upgrade head
python scripts/seed_knowledge.py
```

6. Start development servers:
```bash
# API (terminal 1)
cd apps/api
uvicorn main:app --reload

# Web (terminal 2)
cd apps/web
npm run dev
```

## Key Features

### Document Processing
- Upload military/medical records
- OCR with Azure Document Intelligence
- AI classification (DD214, medical records, etc.)
- Text chunking and embedding for semantic search

### Claim Analysis
- AI identifies potential disability claims
- Service connection analysis (direct, secondary, presumptive)
- Rating estimation based on 38 CFR Part 4
- Evidence gap identification

### Citation Enforcement
All AI outputs must cite source documents:
```
[CITE: document_id="doc-123", page=5, quote="exact text from document"]
```

### Forms Automation
- Auto-fill VA forms (21-526EZ, etc.)
- Field-level citations showing data sources
- Manual override capability
- PDF generation

### Attorney Review
- Checklist-based review workflow
- Comment and revision requests
- Legal/ethical compliance checks
- Approval gates before submission

### VA Submission
- Integration with VA Benefits Intake API
- Human approval required
- Status tracking
- Error handling and retry

## 38 CFR Knowledge Base

The system includes a searchable knowledge base of:
- 38 CFR Part 4 Rating Schedule
- Diagnostic codes and rating criteria
- Service connection guidance
- Fee limitation rules

## API Endpoints

See `/docs` when running the API for full Swagger documentation.

Key endpoints:
- `POST /api/auth/register` - User registration
- `POST /api/documents/upload` - Upload documents
- `POST /api/claims` - Create claims
- `POST /api/claims/{id}/analyze` - Trigger AI analysis
- `POST /api/forms` - Generate VA forms
- `POST /api/reviews` - Create reviews
- `POST /api/submissions` - Submit to VA

## Testing

```bash
cd apps/api
pytest
```

## Deployment

The system deploys to Azure Container Apps using Terraform.

```bash
cd infrastructure/terraform
terraform apply
```

## Security

- All secrets in environment variables
- Azure Key Vault integration
- JWT authentication
- Role-based access control
- Audit logging

## License

Proprietary - All rights reserved

## Disclaimer

This software is for educational and authorized use only. Always verify
information with official VA sources. This is not legal or medical advice.
