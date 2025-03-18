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
from transformers import pipeline


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



phishing_detector = pipeline(
    "text-classification",
    model="dima806/phishing-email-detection",
    truncation=True
)


@csrf_exempt  
def analyze_email(request):
    if request.method == 'POST':
        try:
            
            body = json.loads(request.body)
            email_content = body.get('emailContent', '').strip()

            
            if not email_content:
                return JsonResponse({'error': 'Email content is required'}, status=400)

            
            result = phishing_detector(email_content)[0]

            raw_label = result.get('label', '').upper() 
            score = result.get('score', 0)  

            
            label_mapping = {
                "PHISHING EMAIL": "PHISHING EMAIL",
                "SAVE EMAIL": "SAFE EMAIL"  
            }
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
            return JsonResponse({'error': 'An error occurred while analyzing the email'}, status=500)


    return JsonResponse({'error': 'Invalid request method'}, status=405)