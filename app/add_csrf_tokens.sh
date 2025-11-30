#!/bin/bash

# List of template files with forms
templates=(
    "web/templates/admin/group_create.html"
    "web/templates/admin/users.html"
    "web/templates/admin/user_create.html"
    "web/templates/admin/group_members.html"
    "web/templates/admin/publish.html"
    "web/templates/admin/policy_edit.html"
    "web/templates/admin/groups.html"
    "web/templates/admin/assign.html"
    "web/templates/admin/policies.html"
    "web/templates/admin/new_version.html"
    "web/templates/staff/policy_view.html"
)

for template in "${templates[@]}"; do
    if [ -f "$template" ]; then
        # Check if CSRF token already exists
        if ! grep -q 'name="csrf_token"' "$template"; then
            # Add CSRF token after every <form> tag
            sed -i 's|<form \(.*\)>|<form \1>\n        <input type="hidden" name="csrf_token" value="{{.csrf_token}}">|g' "$template"
            echo "✅ Added CSRF token to $template"
        else
            echo "⏭️  CSRF token already in $template"
        fi
    else
        echo "⚠️  File not found: $template"
    fi
done

echo ""
echo "✅ CSRF tokens added to all forms!"
