from django import forms
from .models import MediaAsset, MediaCategory

SELECT_ATTRS = {'style': 'width:100%;padding:10px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:0.92rem;outline:none;background:#f8fafc;'}

class MediaUploadForm(forms.ModelForm):
    class Meta:
        model  = MediaAsset
        fields = ['title', 'description', 'category', 'tags', 'visibility']
        widgets = {
            'title':       forms.TextInput(attrs={'placeholder': 'Asset title'}),
            'description': forms.Textarea(attrs={'placeholder': 'Describe this asset...', 'rows': 3}),
            'tags':        forms.TextInput(attrs={'placeholder': 'tag1, tag2, tag3'}),
            'category':    forms.Select(attrs=SELECT_ATTRS),
            'visibility':  forms.Select(attrs=SELECT_ATTRS),
        }

class MediaEditForm(forms.ModelForm):
    class Meta:
        model  = MediaAsset
        fields = ['title', 'description', 'category', 'tags', 'visibility', 'status']
        widgets = {
            'title':       forms.TextInput(attrs={'placeholder': 'Asset title'}),
            'description': forms.Textarea(attrs={'placeholder': 'Description', 'rows': 3}),
            'tags':        forms.TextInput(attrs={'placeholder': 'tag1, tag2, tag3'}),
            'category':    forms.Select(attrs=SELECT_ATTRS),
            'visibility':  forms.Select(attrs=SELECT_ATTRS),
            'status':      forms.Select(attrs=SELECT_ATTRS),
        }
