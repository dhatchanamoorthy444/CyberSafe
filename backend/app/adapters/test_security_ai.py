import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from ..adapters.security_ai import explain_findings

class TestSecurityAI:
    """Test suite for Groq AI explanation functionality"""

    @pytest.mark.asyncio
    async def test_explain_findings_no_api_key(self):
        """Test explain_findings when no Groq API key is configured"""
        with patch.dict('os.environ', {'GROQ_API_KEY': ''}):
            result = await explain_findings([{'type': 'phishing', 'severity': 'high'}], 'https://example.com')
            assert result['explanation'] == "AI analysis not configured."
            assert result['risk_summary'] == "N/A."

    @pytest.mark.asyncio
    async def test_explain_findings_api_error(self):
        """Test explain_findings when Groq API returns an error status"""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test-key'}):
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = AsyncMock()
                mock_response.status_code = 500
                mock_response.text = "Internal Server Error"
                mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

                result = await explain_findings([{'type': 'phishing', 'severity': 'high'}], 'https://example.com')
                assert result['explanation'] == "Analysis failed."
                assert result['risk_summary'] == "N/A."

    @pytest.mark.asyncio
    async def test_explain_findings_timeout(self):
        """Test explain_findings when Groq API times out"""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test-key'}):
            with patch('httpx.AsyncClient') as mock_client:
                mock_client.return_value.__aenter__.return_value.post.side_effect = Exception("Timeout")

                result = await explain_findings([{'type': 'phishing', 'severity': 'high'}], 'https://example.com')
                assert result['explanation'] == "Analysis failed."
                assert result['risk_summary'] == "N/A."

    @pytest.mark.asyncio
    async def test_explain_findings_successful_response(self):
        """Test explain_findings when Groq API returns valid JSON"""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test-key'}):
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "choices": [{"message": {"content": '{"explanation": "Test explanation", "risk_summary": "Test risk"}'}}]
                }
                mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

                result = await explain_findings([{'type': 'phishing', 'severity': 'high'}], 'https://example.com')
                assert result['explanation'] == "Test explanation"
                assert result['risk_summary'] == "Test risk"

    @pytest.mark.asyncio
    async def test_explain_findings_malformed_json(self):
        """Test explain_findings when Groq API returns malformed JSON"""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test-key'}):
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "choices": [{"message": {"content": '{"invalid": "json"}'}}]
                }
                mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

                result = await explain_findings([{'type': 'phishing', 'severity': 'high'}], 'https://example.com')
                assert result['explanation'] == "Analysis failed."
                assert result['risk_summary'] == "N/A."

    @pytest.mark.asyncio
    async def test_explain_findings_empty_findings(self):
        """Test explain_findings with empty findings list"""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test-key'}):
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "choices": [{"message": {"content": '{"explanation": "No findings to analyze", "risk_summary": "Low risk"}}}]
                }
                mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

                result = await explain_findings([], 'https://example.com')
                assert result['explanation'] == "No findings to analyze"
                assert result['risk_summary'] == "Low risk"