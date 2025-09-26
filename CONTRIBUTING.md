# Contributing to PhishHunter 🤝

Thank you for your interest in contributing to PhishHunter! This guide will help you get started with contributing to this cybersecurity project.

## 🎯 Ways to Contribute

### 🐛 Bug Reports
- Use the GitHub issue tracker
- Include detailed reproduction steps
- Provide system information (Python version, OS)
- Include relevant log files

### 💡 Feature Requests
- Check existing issues first
- Describe the use case clearly
- Explain why it would benefit the community

### 🔧 Code Contributions
- Fork the repository
- Create a feature branch
- Write tests for new functionality
- Ensure code passes all checks
- Submit a pull request

### 📚 Documentation
- Improve existing documentation
- Add examples and tutorials
- Fix typos and formatting
- Translate documentation

## 🚀 Getting Started

### Development Environment

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YourUsername/phishhunter.git
   cd phishhunter
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Run Tests**
   ```bash
   python -m pytest tests/
   ```

## 📋 Development Guidelines

### Code Style
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions
- Keep functions small and focused

### Code Quality Tools
```bash
# Format code
black phishhunter.py

# Check style
flake8 phishhunter.py

# Type checking
mypy phishhunter.py
```

### Testing
- Write tests for all new functionality
- Maintain minimum 80% test coverage
- Include both unit and integration tests
- Test edge cases and error conditions

### Git Workflow
1. Create a feature branch: `git checkout -b feature/amazing-feature`
2. Make your changes
3. Add tests
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

## 🔒 Security Considerations

### Responsible Security Research
- Do not test against live websites without permission
- Use sandbox environments for testing
- Report security vulnerabilities responsibly

### Code Security
- Never commit API keys or sensitive data
- Use environment variables for configuration
- Validate all user inputs
- Handle errors gracefully

## 📝 Pull Request Process

### Before Submitting
- [ ] Code follows style guidelines
- [ ] Tests are written and passing
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] No merge conflicts

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
```

## 🎨 Adding New Detection Methods

### Detection Method Template
```python
class NewDetectionMethod:
    """Description of what this method detects"""

    def analyze(self, url: str) -> Tuple[float, List[str]]:
        """
        Analyze URL for specific indicators

        Args:
            url: URL to analyze

        Returns:
            Tuple of (risk_score, risk_factors)
        """
        risk_score = 0.0
        risk_factors = []

        # Your detection logic here

        return min(risk_score, 1.0), risk_factors
```

### Integration Steps
1. Add your detection class
2. Integrate with main PhishHunter class
3. Add configuration options
4. Write comprehensive tests
5. Update documentation

## 📚 Documentation Standards

### Docstring Format
```python
def analyze_domain(self, domain: str) -> Dict[str, Any]:
    """
    Analyze domain for phishing indicators.

    Args:
        domain: Domain name to analyze

    Returns:
        Dictionary containing analysis results

    Raises:
        ValueError: If domain is invalid

    Example:
        >>> analyzer = DomainAnalyzer()
        >>> result = analyzer.analyze_domain('example.com')
        >>> print(result['is_suspicious'])
    """
```

### README Updates
- Update feature list for new capabilities
- Add usage examples
- Update configuration documentation
- Include performance benchmarks

## 🧪 Testing Guidelines

### Test Structure
```
tests/
├── unit/
│   ├── test_url_analyzer.py
│   ├── test_domain_checker.py
│   └── test_certificate_analyzer.py
├── integration/
│   ├── test_full_analysis.py
│   └── test_api_integration.py
└── fixtures/
    ├── sample_urls.txt
    └── test_certificates/
```

### Test Naming
- `test_<functionality>_<condition>_<expected_result>`
- Example: `test_url_analyzer_suspicious_tld_high_score`

### Mock External Services
```python
@patch('requests.get')
def test_domain_checker_api_failure(self, mock_get):
    mock_get.side_effect = requests.RequestException("API Error")
    # Test error handling
```

## 🌍 Internationalization

### Adding New Languages
1. Create translation files in `locales/`
2. Use `gettext` for translatable strings
3. Update language selection in config
4. Test with different locales

## 📊 Performance Guidelines

### Optimization Principles
- Minimize external API calls
- Use caching where appropriate
- Implement proper timeout handling
- Profile code for bottlenecks

### Benchmarking
```python
import time
import statistics

def benchmark_detection_method():
    times = []
    for _ in range(100):
        start = time.time()
        result = detector.analyze('https://example.com')
        times.append(time.time() - start)

    print(f"Average time: {statistics.mean(times):.3f}s")
```

## 🏆 Recognition

### Contributor Types
- **Core Contributors**: Maintainers with write access
- **Regular Contributors**: Frequent code contributors
- **Community Contributors**: Documentation, testing, bug reports
- **Security Researchers**: Vulnerability reports and fixes

### Hall of Fame
Contributors will be recognized in:
- README.md contributors section
- Release notes
- Conference presentations
- Academic papers (where applicable)

## 📞 Getting Help

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **Email**: site@hotmail.com for sensitive security issues
- **Discussions**: Use GitHub Discussions for questions

### Response Times
- Security issues: 24-48 hours
- Bug reports: 3-7 days
- Feature requests: 1-2 weeks
- Pull reviews: 3-5 days

## 📜 Code of Conduct

### Our Pledge
We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Standards
- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

### Enforcement
Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at site@hotmail.com.

---

Thank you for contributing to making the internet a safer place! 🛡️
