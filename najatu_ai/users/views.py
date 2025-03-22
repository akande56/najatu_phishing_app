import os
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db.models import QuerySet
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import DetailView
from django.views.generic import RedirectView
from django.views.generic import UpdateView
from najatu_ai.users.models import User


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import requests



class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    slug_field = "id"
    slug_url_kwarg = "id"


user_detail_view = UserDetailView.as_view()


class UserUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = User
    fields = ["name"]
    success_message = _("Information successfully updated")

    def get_success_url(self) -> str:
        assert self.request.user.is_authenticated  # type guard
        return self.request.user.get_absolute_url()

    def get_object(self, queryset: QuerySet or None=None) -> User:
        assert self.request.user.is_authenticated  # type guard
        return self.request.user


user_update_view = UserUpdateView.as_view()


class UserRedirectView(LoginRequiredMixin, RedirectView):
    permanent = False

    def get_redirect_url(self) -> str:
        return reverse("users:detail", kwargs={"pk": self.request.user.pk})


user_redirect_view = UserRedirectView.as_view()



API_URL = os.getenv("API_URL")
HEADERS = {
    "Authorization": f"Bearer {os.getenv('HF_API_TOKEN')}", 
    "Content-Type": "application/json"
}




@csrf_exempt  
def analyze_email(request):
    if request.method == 'POST':
        try:
            # Parse the incoming JSON request
            body = json.loads(request.body)
            email_content = body.get('emailContent', '').strip()

            if not email_content:
                return JsonResponse({'error': 'Email content is required'}, status=400)

            # Send the email content to the Hugging Face API
            payload = {"inputs": email_content}
            response = requests.post(API_URL, headers=HEADERS, json=payload)

            # Check if the API request was successful
            if response.status_code != 200:
                return JsonResponse({'error': 'Failed to analyze email'}, status=500)

            # Parse the API response
            result = response.json()  # This is a nested list: [[{'label': ..., 'score': ...}, {...}]]
            
            # Ensure the response is in the expected format
            if not isinstance(result, list) or len(result) == 0 or not isinstance(result[0], list):
                return JsonResponse({'error': 'Unexpected API response format'}, status=500)

            # Extract the top prediction
            predictions = result[0]  # Get the inner list of predictions
            top_result = predictions[0]  # Get the most likely label
            raw_label = top_result.get('label', '').upper()
            score = top_result.get('score', 0)

            # Map labels to user-friendly names
            label_mapping = {"PHISHING EMAIL": "PHISHING EMAIL", "SAFE EMAIL": "SAFE EMAIL"}
            normalized_label = label_mapping.get(raw_label, "UNKNOWN")
            is_phishing = normalized_label == "PHISHING EMAIL"

            # Prepare the response
            prediction = {
                'score': round(score * 100, 2),
                'confidence': round(score * 100, 2),
                'details': f"Label: {normalized_label}",
                'isPhishing': is_phishing
            }

            return JsonResponse(prediction)

        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            return JsonResponse({'error': 'An error occurred while analyzing the email'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)