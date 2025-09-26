#!/usr/bin/env python3
"""
PhishHunter Usage Examples
Author: Ali AlEnezi

This script demonstrates various ways to use PhishHunter for detecting phishing websites.
"""

from phishhunter import PhishHunter
import json
import time

def basic_usage_example():
    """Basic usage example"""
    print("🔍 Basic Usage Example")
    print("=" * 50)

    # Initialize PhishHunter
    hunter = PhishHunter()

    # Test URLs (using safe examples)
    test_urls = [
        'https://github.com',  # Safe
        'https://suspicious-paypal-login.tk',  # Suspicious (example)
        'https://secure-bank-update.ml'  # Suspicious (example)
    ]

    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        try:
            result = hunter.analyze_url(url)
            status = "🚨 PHISHING" if result.is_phishing else "✅ SAFE"
            print(f"Status: {status}")
            print(f"Confidence: {result.confidence_score:.1%}")
            print(f"Risk Factors: {', '.join(result.risk_factors)}")
        except Exception as e:
            print(f"❌ Error: {e}")

def batch_analysis_example():
    """Batch analysis example"""
    print("\n\n📋 Batch Analysis Example")
    print("=" * 50)

    hunter = PhishHunter()

    # Multiple URLs for batch processing
    urls = [
        'https://google.com',
        'https://microsoft.com',
        'https://fake-amazon-security.tk',  # Example
        'https://phishing-test.com'  # Example
    ]

    print(f"Analyzing {len(urls)} URLs in batch...")
    start_time = time.time()

    results = hunter.batch_analyze(urls)

    end_time = time.time()

    print(f"Analysis completed in {end_time - start_time:.2f} seconds")

    # Display results
    for result in results:
        status = "🚨 PHISHING" if result.is_phishing else "✅ SAFE"
        print(f"{result.url}: {status} ({result.confidence_score:.1%})")

def custom_configuration_example():
    """Custom configuration example"""
    print("\n\n⚙️ Custom Configuration Example")
    print("=" * 50)

    # Create custom config
    custom_config = {
        'detection_settings': {
            'confidence_threshold': 0.8,  # Higher threshold
            'max_workers': 10
        },
        'phishing_keywords': [
            'urgent', 'immediate', 'action', 'required',
            'suspend', 'verification', 'confirm'
        ]
    }

    # Initialize with custom config
    hunter = PhishHunter()
    hunter.config.update(custom_config)

    # Test with custom configuration
    result = hunter.analyze_url('https://urgent-account-verification.example.com')
    print(f"Custom analysis result: {result.confidence_score:.1%}")

def detailed_analysis_example():
    """Detailed analysis with full output"""
    print("\n\n🔬 Detailed Analysis Example")
    print("=" * 50)

    hunter = PhishHunter()

    # Analyze with detailed output
    result = hunter.analyze_url('https://github.com')

    print(f"URL: {result.url}")
    print(f"Is Phishing: {result.is_phishing}")
    print(f"Confidence Score: {result.confidence_score:.3f}")
    print(f"Detection Methods Used: {result.detection_methods}")
    print(f"Risk Factors: {result.risk_factors}")
    print(f"Analysis Timestamp: {result.timestamp}")

    print("\nDetailed Results:")
    for method, details in result.details.items():
        print(f"  {method}: Score={details['score']:.3f}, Risks={details['risks']}")

def save_results_example():
    """Example of saving results to files"""
    print("\n\n💾 Save Results Example")
    print("=" * 50)

    hunter = PhishHunter()

    # Analyze some URLs
    urls = [
        'https://github.com',
        'https://stackoverflow.com',
        'https://suspicious-example.tk'
    ]

    results = hunter.batch_analyze(urls)

    # Save as JSON
    hunter.save_results(results, 'example_results.json')
    print("✅ Results saved to example_results.json")

    # Save as CSV
    hunter.save_results(results, 'example_results.csv')
    print("✅ Results saved to example_results.csv")

def monitor_specific_brands_example():
    """Example of monitoring for specific brand impersonation"""
    print("\n\n🏢 Brand Monitoring Example")
    print("=" * 50)

    hunter = PhishHunter()

    # URLs that might impersonate popular brands
    suspicious_urls = [
        'https://paypa1-secure.com',  # Note the '1' instead of 'l'
        'https://amazon-security-alert.tk',
        'https://microsoft-account-verify.ml',
        'https://app1e-id-locked.ga'  # Note the '1' instead of 'l'
    ]

    brand_targets = ['paypal', 'amazon', 'microsoft', 'apple']

    print(f"Monitoring for impersonation of: {', '.join(brand_targets)}")

    for url in suspicious_urls:
        result = hunter.analyze_url(url)

        # Check if any brand keywords are found
        url_lower = url.lower()
        detected_brands = [brand for brand in brand_targets if brand in url_lower]

        if detected_brands and result.is_phishing:
            print(f"🚨 BRAND IMPERSONATION DETECTED!")
            print(f"   URL: {url}")
            print(f"   Impersonating: {', '.join(detected_brands)}")
            print(f"   Confidence: {result.confidence_score:.1%}")

if __name__ == '__main__':
    print("🎣 PhishHunter Usage Examples")
    print("=" * 60)
    print("Author: Ali AlEnezi <site@hotmail.com>")
    print("GitHub: https://github.com/SiteQ8/phishhunter")
    print("=" * 60)

    try:
        # Run all examples
        basic_usage_example()
        batch_analysis_example()
        custom_configuration_example()
        detailed_analysis_example()
        save_results_example()
        monitor_specific_brands_example()

        print("\n\n✅ All examples completed successfully!")
        print("📚 Check the generated files:")
        print("   - example_results.json")
        print("   - example_results.csv")

    except Exception as e:
        print(f"❌ Error running examples: {e}")
        print("💡 Make sure PhishHunter is properly installed and configured")
