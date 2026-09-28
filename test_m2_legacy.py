import os
os.environ['M2_MODEL_PATH'] = 'ml_models/lightclassifier'
from app.services.ml.m2_intent_classifier import M2IntentClassifier

m2 = M2IntentClassifier()
print(m2._analyze_intent('This is a benign email about lunch tomorrow.'))
