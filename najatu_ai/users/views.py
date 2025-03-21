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
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
import torch
import torch.nn as nn

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



# Load the pre-trained model
model = AutoModelForSequenceClassification.from_pretrained("dima806/phishing-email-detection")

# Apply dynamic quantization (CPU-only)
model = torch.quantization.quantize_dynamic(
    model, 
    {nn.Linear},  # Quantize all linear layers
    dtype=torch.qint8  # 8-bit integer precision
)

# Move model to CPU explicitly
device = torch.device("cpu")
model.to(device)
model.eval()

# Initialize tokenizer
tokenizer = AutoTokenizer.from_pretrained("dima806/phishing-email-detection")

# Initialize pipeline (optional, but ensures compatibility)
phishing_detector = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    device=device  # Explicitly use CPU
)


@csrf_exempt  
def analyze_email(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            email_content = body.get('emailContent', '').strip()

            if not email_content:
                return JsonResponse({'error': 'Email content is required'}, status=400)

            # Disable gradient calculation to save memory
            with torch.no_grad():
                result = phishing_detector(email_content)[0]

            # Process results (same as before)
            raw_label = result.get('label', '').upper()
            score = result.get('score', 0)
            label_mapping = {"PHISHING EMAIL": "PHISHING EMAIL", "SAFE EMAIL": "SAFE EMAIL"}
            normalized_label = label_mapping.get(raw_label, "UNKNOWN")
            is_phishing = normalized_label == "PHISHING EMAIL"

            prediction = {
                'score': round(score * 100, 2),
                'confidence': round(score * 100, 2),
                'details': f"Label: {normalized_label}",
                'isPhishing': is_phishing
            }

            return JsonResponse(prediction)

        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            return JsonResponse({'error': 'An error occurred'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)