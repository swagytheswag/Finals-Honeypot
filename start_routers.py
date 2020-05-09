from router50000 import Router50000
from router40000 import Router40000
from father_router import FatherRouter


father_router = FatherRouter("10.0.0.8", "10.0.0.9") # Initialize the router object

router50000 = Router50000(father_router)
router50000.start_router()
router40000 = Router40000(father_router)
router40000.start_router()
