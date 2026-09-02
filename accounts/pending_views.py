
# Append to accounts/views.py

@login_required
def pending_approval_view(request):
    return render(request, 'accounts/pending_approval.html')
