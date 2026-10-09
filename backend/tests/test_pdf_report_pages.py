import os
import sys
import pypdf

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from reports.pdf_gen import generate_pdf_report
from reports.charts import generate_charts

def test_generate_8_page_report():
    mock_data = {
        'total_passwords': 1666,
        'unique_passwords': 1666,
        'average_length': 8.1,
        'median_length': 8.0,
        'std_dev_length': 1.1,
        'min_length': 6,
        'max_length': 17,
        'risk_score': 49.1,
        'risk_level': 'Medium',
        'org_name': 'Hardik Enterprise',
        'company_domain': 'acme.com',
        'company_industry': 'Enterprise Technology',
        'ciso_name': 'Chief Information Security Officer (CISO)',
        'min_length_req': 14,
        'inactivity_timeout': 10,
        'length_distribution': {'less_than_8': 336, '8_to_11': 1000, '12_to_15': 300, '16_plus': 30},
        'risk_distribution': {'high': 833, 'medium': 833, 'low': 0},
        'patterns': {
            'dictionary_based': {'percentage': 50.0, 'count': 833},
            'keyboard_walk': {'percentage': 25.0, 'count': 416},
            'numeric_suffix': {'percentage': 25.0, 'count': 416},
            'leetspeak': {'percentage': 75.0, 'count': 1249},
        },
        'attack_scenarios': [
            {'name': 'Dictionary Attack', 'count': 33, 'probability': 2.0},
            {'name': 'Keyboard Walk Attack', 'count': 43, 'probability': 2.6},
            {'name': 'Brute Force Estimate', 'count': 203, 'probability': 12.2},
            {'name': 'Pattern Attack', 'count': 1231, 'probability': 73.9},
        ],
        'policy_simulation': {
            'minimum_length_12': 10.4,
            'keyboard_pattern_blocking': 4.0,
            'dictionary_blocking': 3.6,
            'duplicate_prevention': 0.0,
            'sequential_blocking': 0.0,
        },
        'compliance': {
            'compliance_scores': {
                'HIPAA': 49.1,
                'OWASP': 34.4,
                'ISO 27001': 31.9,
                'NIST SP 800-63B': 29.5,
                'PCI-DSS v4.0': 28.5,
            }
        },
        'company_ai_policy': {
            'threat_exposure': 'Hardik Enterprise operates a SaaS platform that stores and processes customer data in multi-tenant cloud environments, making it a high-value target for credential-stuffing and cloud-resource hijacking. The recent audit shows a 34.7% weak-password rate, indicating exposure to automated password-guessing attacks and lateral movement within cloud services.',
            'forbidden_patterns': ['hardik', 'enterprise', 'hardikenterprise', 'hardik2023', 'cloud2024', 'admin'],
            'staff_guidelines': {
                'dos': [
                    'Create a passphrase of at least 18 characters using unrelated words, numbers, and symbols',
                    'Store MFA devices securely and never share them with colleagues',
                    'Use a reputable password manager to generate and store unique passwords for each service',
                    'Review login alerts regularly and report any unexpected activity immediately'
                ],
                'donts': [
                    'Reuse passwords across cloud services, internal tools, or personal accounts',
                    'Include obvious company identifiers such as hardik or enterprise in passwords',
                    'Write passwords on sticky notes or store them in unencrypted files'
                ]
            }
        }
    }

    charts = generate_charts(
        dataset_stats={'length_distribution': mock_data['length_distribution'], 'total_passwords': 1666},
        risk_data={'score': 49.1, 'risk_level': 'Medium', 'distribution': mock_data['risk_distribution']},
        pattern_stats={'patterns': mock_data['patterns']},
        attack_scenarios=mock_data['attack_scenarios'],
        compliance_data=mock_data['compliance']
    )

    out_pdf = generate_pdf_report(mock_data, charts, output_dir='scratch')
    assert os.path.exists(out_pdf), 'PDF file not created'

    reader = pypdf.PdfReader(out_pdf)
    page_count = len(reader.pages)
    print(f'Report compiled successfully. Pages: {page_count}')
    assert page_count == 8, f'Expected 8 pages, got {page_count}'

if __name__ == '__main__':
    test_generate_8_page_report()
