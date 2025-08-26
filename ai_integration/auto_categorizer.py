"""
AI-powered auto-categorization system for vulnerability content
Enhanced for VulnPublisherPro - AI Integration
By RafalW3bCraft | MIT License
"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

class AutoCategorizer:
    """AI-powered vulnerability categorization system"""
    
    def __init__(self):
        self.categorization_rules = {}
        self.tag_vocabulary = {}
        self.category_models = {}
        
        # Initialize categorization components
        self._initialize_categorization_rules()
        self._initialize_tag_vocabulary()
        self._initialize_category_models()
        
        logger.info("AutoCategorizer initialized successfully")
    
    def _initialize_categorization_rules(self):
        """Initialize categorization rules and patterns"""
        self.categorization_rules = {
            'injection': {
                'patterns': [
                    r'sql\s+injection', r'xss', r'cross\s*site\s*scripting',
                    r'command\s+injection', r'code\s+injection',
                    r'ldap\s+injection', r'xml\s+injection'
                ],
                'keywords': ['inject', 'payload', 'execute', 'bypass', 'sanitize'],
                'severity_indicators': ['remote code execution', 'data breach'],
                'confidence_weight': 0.9
            },
            'authentication': {
                'patterns': [
                    r'authentication\s+bypass', r'broken\s+authentication',
                    r'session\s+management', r'password\s+reset',
                    r'login\s+bypass', r'credential\s+stuffing',
                    r'brute\s+force', r'weak\s+password'
                ],
                'keywords': ['login', 'session', 'token', 'credential', 'password'],
                'severity_indicators': ['privilege escalation', 'account takeover'],
                'confidence_weight': 0.85
            },
            'access_control': {
                'patterns': [
                    r'privilege\s+escalation', r'authorization\s+bypass',
                    r'access\s+control', r'idor', r'insecure\s+direct\s+object',
                    r'vertical\s+privilege', r'horizontal\s+privilege'
                ],
                'keywords': ['access', 'permission', 'role', 'privilege', 'authorization'],
                'severity_indicators': ['admin access', 'system compromise'],
                'confidence_weight': 0.8
            },
            'cryptographic': {
                'patterns': [
                    r'cryptographic\s+failure', r'weak\s+encryption',
                    r'ssl/tls', r'certificate\s+validation',
                    r'hash\s+collision', r'weak\s+cipher'
                ],
                'keywords': ['encrypt', 'decrypt', 'hash', 'cipher', 'certificate'],
                'severity_indicators': ['data exposure', 'man-in-the-middle'],
                'confidence_weight': 0.75
            },
            'information_disclosure': {
                'patterns': [
                    r'information\s+disclosure', r'data\s+exposure',
                    r'sensitive\s+data', r'directory\s+traversal',
                    r'path\s+traversal', r'file\s+inclusion'
                ],
                'keywords': ['leak', 'expose', 'disclosure', 'sensitive', 'confidential'],
                'severity_indicators': ['data breach', 'privacy violation'],
                'confidence_weight': 0.7
            },
            'denial_of_service': {
                'patterns': [
                    r'denial\s+of\s+service', r'dos\s+attack',
                    r'resource\s+exhaustion', r'buffer\s+overflow',
                    r'memory\s+exhaustion', r'cpu\s+exhaustion'
                ],
                'keywords': ['crash', 'hang', 'exhaust', 'overflow', 'flood'],
                'severity_indicators': ['service disruption', 'availability impact'],
                'confidence_weight': 0.65
            }
        }
    
    def _initialize_tag_vocabulary(self):
        """Initialize tag vocabulary and scoring"""
        self.tag_vocabulary = {
            'vulnerability_types': [
                'sql-injection', 'xss', 'csrf', 'rce', 'lfi', 'rfi', 
                'xxe', 'ssrf', 'deserialization', 'command-injection',
                'path-traversal', 'privilege-escalation', 'authentication-bypass',
                'authorization-bypass', 'information-disclosure', 'dos'
            ],
            'attack_vectors': [
                'remote', 'local', 'network', 'web', 'physical', 'social-engineering'
            ],
            'affected_components': [
                'web-application', 'api', 'database', 'network', 'mobile-app',
                'iot-device', 'cloud-service', 'operating-system'
            ],
            'severity_levels': [
                'critical', 'high', 'medium', 'low', 'informational'
            ],
            'exploitation_difficulty': [
                'trivial', 'easy', 'moderate', 'difficult', 'expert-level'
            ]
        }
    
    def _initialize_category_models(self):
        """Initialize categorization models and classifiers"""
        self.category_models = {
            'text_classifier': None,  # Would be trained ML model
            'pattern_matcher': self._create_pattern_matcher(),
            'severity_classifier': self._create_severity_classifier(),
            'impact_assessor': self._create_impact_assessor()
        }
        
    def _create_pattern_matcher(self):
        """Create pattern matching classifier"""
        return {
            'compiled_patterns': {},
            'keyword_weights': {},
            'context_analysis': True
        }
    
    def _create_severity_classifier(self):
        """Create severity classification system"""
        return {
            'cvss_mapping': {
                'critical': (9.0, 10.0),
                'high': (7.0, 8.9),
                'medium': (4.0, 6.9),
                'low': (0.1, 3.9),
                'none': (0.0, 0.0)
            },
            'impact_factors': ['confidentiality', 'integrity', 'availability'],
            'exploitability_factors': ['attack_vector', 'attack_complexity', 'privileges_required']
        }
    
    def _create_impact_assessor(self):
        """Create impact assessment system"""
        return {
            'business_impact': ['financial', 'operational', 'reputational', 'regulatory'],
            'technical_impact': ['data_loss', 'system_compromise', 'service_disruption'],
            'user_impact': ['privacy_breach', 'account_compromise', 'data_exposure']
        }
    
    def categorize_vulnerability(self, content: Dict[str, Any], confidence_threshold: float = 0.7) -> Dict[str, Any]:
        """Categorize vulnerability using AI-powered analysis"""
        try:
            categorization_result = {
                'primary_category': None,
                'secondary_categories': [],
                'confidence_scores': {},
                'suggested_tags': [],
                'severity_assessment': None,
                'impact_analysis': {},
                'remediation_priority': None,
                'analysis_metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'confidence_threshold': confidence_threshold,
                    'analysis_method': 'ai_powered_categorization'
                }
            }
            
            # Extract text content for analysis
            text_content = self._extract_text_content(content)
            
            # Pattern-based categorization
            pattern_scores = self._analyze_patterns(text_content)
            
            # Keyword-based analysis
            keyword_scores = self._analyze_keywords(text_content)
            
            # Combine scores
            combined_scores = self._combine_scores(pattern_scores, keyword_scores)
            
            # Determine primary category
            if combined_scores:
                primary_category = max(combined_scores.items(), key=lambda x: x[1])
                if primary_category[1] >= confidence_threshold:
                    categorization_result['primary_category'] = primary_category[0]
                    categorization_result['confidence_scores'][primary_category[0]] = primary_category[1]
            
            # Find secondary categories
            for category, score in combined_scores.items():
                if score >= confidence_threshold * 0.7 and category != categorization_result['primary_category']:
                    categorization_result['secondary_categories'].append({
                        'category': category,
                        'confidence': score
                    })
            
            # Generate tags
            categorization_result['suggested_tags'] = self._generate_tags(content, combined_scores)
            
            # Assess severity
            categorization_result['severity_assessment'] = self._assess_severity(content, categorization_result['primary_category'])
            
            # Analyze impact
            categorization_result['impact_analysis'] = self._analyze_impact(content, categorization_result['primary_category'])
            
            # Determine remediation priority
            categorization_result['remediation_priority'] = self._determine_remediation_priority(
                categorization_result['severity_assessment'],
                categorization_result['impact_analysis']
            )
            
            logger.info(f"Categorized vulnerability: {categorization_result['primary_category']}")
            return categorization_result
            
        except Exception as e:
            logger.error(f"Error in vulnerability categorization: {e}")
            return {
                'error': str(e),
                'primary_category': 'unknown',
                'confidence_scores': {},
                'analysis_metadata': {'timestamp': datetime.now().isoformat()}
            }
    
    def _extract_text_content(self, content: Dict[str, Any]) -> str:
        """Extract and clean text content for analysis"""
        text_parts = []
        
        # Extract from common fields
        for field in ['title', 'description', 'summary', 'details']:
            if field in content and content[field]:
                text_parts.append(str(content[field]))
        
        # Join and clean
        full_text = ' '.join(text_parts).lower()
        
        # Remove special characters but keep spaces and basic punctuation
        cleaned_text = re.sub(r'[^\w\s\-\.]', ' ', full_text)
        
        return cleaned_text
    
    def _analyze_patterns(self, text: str) -> Dict[str, float]:
        """Analyze text using regex patterns"""
        pattern_scores = defaultdict(float)
        
        for category, rules in self.categorization_rules.items():
            category_score = 0.0
            pattern_matches = 0
            
            # Check patterns
            for pattern in rules.get('patterns', []):
                if re.search(pattern, text, re.IGNORECASE):
                    pattern_matches += 1
                    category_score += 0.3
            
            # Apply pattern weight
            if pattern_matches > 0:
                pattern_scores[category] = min(category_score * rules.get('confidence_weight', 1.0), 1.0)
        
        return dict(pattern_scores)
    
    def _analyze_keywords(self, text: str) -> Dict[str, float]:
        """Analyze text using keyword matching"""
        keyword_scores = defaultdict(float)
        
        for category, rules in self.categorization_rules.items():
            keyword_matches = 0
            total_keywords = len(rules.get('keywords', []))
            
            if total_keywords == 0:
                continue
                
            for keyword in rules.get('keywords', []):
                if keyword in text:
                    keyword_matches += 1
            
            # Calculate keyword score
            if keyword_matches > 0:
                keyword_score = (keyword_matches / total_keywords) * 0.5
                keyword_scores[category] = min(keyword_score * rules.get('confidence_weight', 1.0), 1.0)
        
        return dict(keyword_scores)
    
    def _combine_scores(self, pattern_scores: Dict[str, float], keyword_scores: Dict[str, float]) -> Dict[str, float]:
        """Combine pattern and keyword scores"""
        combined = defaultdict(float)
        
        # Combine scores with weights
        all_categories = set(pattern_scores.keys()) | set(keyword_scores.keys())
        
        for category in all_categories:
            pattern_score = pattern_scores.get(category, 0.0)
            keyword_score = keyword_scores.get(category, 0.0)
            
            # Weighted combination (patterns have more weight)
            combined_score = (pattern_score * 0.7) + (keyword_score * 0.3)
            combined[category] = min(combined_score, 1.0)
        
        return dict(combined)
    
    def _generate_tags(self, content: Dict[str, Any], category_scores: Dict[str, float]) -> List[str]:
        """Generate relevant tags based on categorization"""
        tags = []
        
        # Add primary category tag
        if category_scores:
            primary_category = max(category_scores.items(), key=lambda x: x[1])[0]
            tags.append(primary_category.replace('_', '-'))
        
        # Add severity tag
        severity = content.get('severity', '').lower()
        if severity in ['critical', 'high', 'medium', 'low']:
            tags.append(f'severity-{severity}')
        
        # Add CVE tag if present
        if 'cve' in str(content).lower():
            tags.append('cve')
        
        # Add exploit tag if mentioned
        text_content = self._extract_text_content(content).lower()
        if any(word in text_content for word in ['exploit', 'poc', 'proof of concept']):
            tags.append('exploit-available')
        
        # Add tags based on affected components
        if 'web' in text_content or 'http' in text_content:
            tags.append('web-application')
        if 'database' in text_content or 'sql' in text_content:
            tags.append('database')
        if 'api' in text_content:
            tags.append('api')
        
        return list(set(tags))  # Remove duplicates
    
    def _assess_severity(self, content: Dict[str, Any], category: Optional[str]) -> Dict[str, Any]:
        """Assess vulnerability severity"""
        severity_assessment = {
            'level': 'medium',
            'score': 5.0,
            'factors': [],
            'rationale': ''
        }
        
        try:
            # Extract severity from content
            if 'severity' in content:
                severity_assessment['level'] = content['severity'].lower()
            
            # Extract CVSS score if available
            if 'cvss_score' in content:
                severity_assessment['score'] = float(content['cvss_score'])
            
            # Assess based on category
            if category:
                category_severity = self._get_category_severity(category)
                severity_assessment['factors'].append(f"Category: {category}")
                
                # Adjust score based on category
                if category_severity == 'high':
                    severity_assessment['score'] = max(severity_assessment['score'], 7.0)
                elif category_severity == 'critical':
                    severity_assessment['score'] = max(severity_assessment['score'], 8.5)
            
            # Check for severity indicators
            text_content = self._extract_text_content(content)
            for category_rules in self.categorization_rules.values():
                for indicator in category_rules.get('severity_indicators', []):
                    if indicator.lower() in text_content:
                        severity_assessment['factors'].append(f"High-risk indicator: {indicator}")
                        severity_assessment['score'] = min(severity_assessment['score'] + 1.0, 10.0)
            
            # Map score to level
            if severity_assessment['score'] >= 9.0:
                severity_assessment['level'] = 'critical'
            elif severity_assessment['score'] >= 7.0:
                severity_assessment['level'] = 'high'
            elif severity_assessment['score'] >= 4.0:
                severity_assessment['level'] = 'medium'
            else:
                severity_assessment['level'] = 'low'
            
            severity_assessment['rationale'] = f"Assessed as {severity_assessment['level']} based on score {severity_assessment['score']:.1f} and factors: {', '.join(severity_assessment['factors'])}"
            
        except Exception as e:
            logger.error(f"Error assessing severity: {e}")
            severity_assessment['rationale'] = f"Default assessment due to error: {str(e)}"
        
        return severity_assessment
    
    def _get_category_severity(self, category: str) -> str:
        """Get typical severity for a vulnerability category"""
        high_risk_categories = ['injection', 'authentication', 'access_control']
        critical_risk_categories = ['injection']  # SQL injection, RCE etc.
        
        if category in critical_risk_categories:
            return 'critical'
        elif category in high_risk_categories:
            return 'high'
        else:
            return 'medium'
    
    def _analyze_impact(self, content: Dict[str, Any], category: Optional[str]) -> Dict[str, Any]:
        """Analyze potential impact of vulnerability"""
        impact_analysis = {
            'confidentiality': 'medium',
            'integrity': 'medium', 
            'availability': 'medium',
            'business_impact': [],
            'technical_impact': [],
            'affected_users': 'some',
            'data_at_risk': []
        }
        
        try:
            text_content = self._extract_text_content(content)
            
            # Analyze CIA impact based on category
            if category == 'injection':
                impact_analysis['confidentiality'] = 'high'
                impact_analysis['integrity'] = 'high'
                impact_analysis['data_at_risk'] = ['user_data', 'application_data', 'database_contents']
            
            elif category == 'information_disclosure':
                impact_analysis['confidentiality'] = 'high'
                impact_analysis['data_at_risk'] = ['sensitive_information', 'personal_data']
            
            elif category == 'denial_of_service':
                impact_analysis['availability'] = 'high'
                impact_analysis['business_impact'] = ['service_disruption', 'user_experience_degradation']
            
            # Check for specific impact indicators
            if 'database' in text_content:
                impact_analysis['data_at_risk'].append('database_records')
            
            if 'admin' in text_content or 'administrator' in text_content:
                impact_analysis['affected_users'] = 'administrators'
                impact_analysis['business_impact'].append('admin_compromise')
            
            if 'payment' in text_content or 'financial' in text_content:
                impact_analysis['business_impact'].append('financial_loss')
                impact_analysis['data_at_risk'].append('financial_data')
            
        except Exception as e:
            logger.error(f"Error analyzing impact: {e}")
        
        return impact_analysis
    
    def _determine_remediation_priority(self, severity: Dict[str, Any], impact: Dict[str, Any]) -> str:
        """Determine remediation priority"""
        severity_level = severity.get('level', 'medium')
        business_impact = impact.get('business_impact', [])
        
        # Critical priority conditions
        if (severity_level == 'critical' or 
            'financial_loss' in business_impact or 
            'admin_compromise' in business_impact):
            return 'immediate'
        
        # High priority conditions  
        elif (severity_level == 'high' or
              len(business_impact) >= 2):
            return 'urgent'
        
        # Medium priority
        elif severity_level == 'medium':
            return 'standard'
        
        # Low priority
        else:
            return 'low'
    
    def suggest_tags(self, content: Dict[str, Any], max_tags: int = 10) -> List[Dict[str, Any]]:
        """Suggest tags for vulnerability content"""
        try:
            # First categorize to get base tags
            categorization = self.categorize_vulnerability(content, confidence_threshold=0.5)
            suggested_tags = categorization.get('suggested_tags', [])
            
            # Add additional contextual tags
            text_content = self._extract_text_content(content)
            
            # Technology-specific tags
            tech_tags = self._identify_technologies(text_content)
            suggested_tags.extend(tech_tags)
            
            # Platform tags
            platform_tags = self._identify_platforms(text_content)
            suggested_tags.extend(platform_tags)
            
            # Convert to structured format with confidence scores
            tag_results = []
            for tag in list(set(suggested_tags))[:max_tags]:  # Remove duplicates and limit
                confidence = self._calculate_tag_confidence(tag, text_content)
                tag_results.append({
                    'tag': tag,
                    'confidence': confidence,
                    'category': self._get_tag_category(tag)
                })
            
            # Sort by confidence
            tag_results.sort(key=lambda x: x['confidence'], reverse=True)
            
            return tag_results
            
        except Exception as e:
            logger.error(f"Error suggesting tags: {e}")
            return []
    
    def _identify_technologies(self, text: str) -> List[str]:
        """Identify technologies mentioned in text"""
        tech_keywords = {
            'php': 'php',
            'python': 'python',
            'java': 'java',
            'javascript': 'javascript',
            'nodejs': 'nodejs',
            'react': 'react',
            'angular': 'angular',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'mongodb': 'mongodb',
            'apache': 'apache',
            'nginx': 'nginx',
            'docker': 'docker',
            'kubernetes': 'kubernetes'
        }
        
        found_tech = []
        for keyword, tag in tech_keywords.items():
            if keyword in text:
                found_tech.append(tag)
        
        return found_tech
    
    def _identify_platforms(self, text: str) -> List[str]:
        """Identify platforms mentioned in text"""
        platform_keywords = {
            'windows': 'windows',
            'linux': 'linux',
            'macos': 'macos',
            'android': 'android',
            'ios': 'ios',
            'aws': 'aws',
            'azure': 'azure',
            'gcp': 'gcp',
            'cloud': 'cloud'
        }
        
        found_platforms = []
        for keyword, tag in platform_keywords.items():
            if keyword in text:
                found_platforms.append(tag)
        
        return found_platforms
    
    def _calculate_tag_confidence(self, tag: str, text: str) -> float:
        """Calculate confidence score for a tag"""
        # Simple confidence calculation based on keyword presence
        if tag in text:
            return 0.9
        elif any(word in text for word in tag.split('-')):
            return 0.7
        else:
            return 0.5
    
    def _get_tag_category(self, tag: str) -> str:
        """Get category for a tag"""
        if tag in ['critical', 'high', 'medium', 'low']:
            return 'severity'
        elif tag in ['php', 'python', 'java', 'javascript']:
            return 'technology'
        elif tag in ['windows', 'linux', 'macos']:
            return 'platform'
        else:
            return 'general'