from django.shortcuts import render
from .services import scan_uploaded_file
from .db import collection

def index(request):
    return render(request, "index.html")


def scan_file(request):
    if request.method == "POST":
        scan_type = request.POST.get("scan_type")

        # Folder Scan
        if scan_type == "folder":
            files = request.FILES.getlist("files")
            results = [scan_uploaded_file(f) for f in files]
            return render(request, "result.html", {"results": results})

        # Single File Scan
        elif scan_type == "file":
            file = request.FILES.get("file")
            result = scan_uploaded_file(file)
            return render(request, "result.html", result)

    return render(request, "index.html")


def history(request):
    data = collection.find().sort("time", -1)
    return render(request, "history.html", {"data": data})